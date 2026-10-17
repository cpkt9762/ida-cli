"""Per-connection lifetime admission; no failure here stops the business bridge."""
import logging
from pathlib import Path
import socket

LOG = logging.getLogger(__name__)


class LifetimeListener:
    def init_lifetimes(self, capacity):
        self.lifetime_capacity = capacity
        self.lifetimes = {}
        self.lifetime_pending = {}
        self.lifetime_healthy = False
        self.lifetime_socket = self.new_lifetime_listener()

    def new_lifetime_listener(self):
        listener = socket.socket(socket.AF_UNIX)
        bound_inode = None
        try:
            listener.bind(self.lifetime_path)
            bound_inode = Path(self.lifetime_path).lstat().st_ino
            listener.listen(self.lifetime_capacity)
            listener.settimeout(.2)
            self.lifetime_inode = Path(self.lifetime_path).lstat().st_ino
            self.lifetime_healthy = True
            return listener
        except BaseException:
            listener.close()
            if bound_inode is not None:
                try:
                    if Path(self.lifetime_path).lstat().st_ino == bound_inode:
                        Path(self.lifetime_path).unlink()
                except FileNotFoundError:
                    pass
            raise

    def recover_lifetime_listener(self, failed):
        with self.lock:
            self.lifetime_healthy = False
            if self.stopped.is_set():
                return False
            try:
                if self.lifetime_socket is not failed:
                    return True
                if self.lifetime_inode is not None:
                    if Path(self.lifetime_path).lstat().st_ino != self.lifetime_inode:
                        raise OSError('lifetime endpoint replaced; recovery refused')
                    failed.close()
                    Path(self.lifetime_path).unlink()
                    self.lifetime_inode = None
                # Only our successful unlink authorizes retry on an absent path.
                # bind still refuses a replacement created in the meantime.
                self.lifetime_socket = self.new_lifetime_listener()
                LOG.warning('lifetime listener recovered')
                return True
            except OSError:
                LOG.exception('lifetime listener unhealthy; exact endpoint recovery failed')
                return False

    def accept_lifetimes(self):
        while not self.stopped.is_set():
            listener = self.lifetime_socket
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if not self.stopped.is_set():
                    LOG.exception('lifetime listener unhealthy')
                    if not self.recover_lifetime_listener(listener):
                        self.stopped.wait(.05)
                continue
            # Handshake errors have a different failure domain from accept().
            try:
                self.accept_lifetime(connection)
            except (OSError, UnicodeError, ValueError):
                LOG.warning('lifetime connection handshake rejected', exc_info=True)
                connection.close()

    def lifetime_eligible(self, lease_id, stored):
        return (stored is not None and self.handles.get(lease_id) is stored
                and stored[1].connected and not self.stopped.is_set()
                and not any(record.get('handle') is stored[1] and record.get('cancel_requested')
                            for record in self.executing.values()))

    def accept_lifetime(self, connection):
        installed = False
        previous = None
        token = None
        lease_id = None
        try:
            connection.settimeout(2)
            raw = connection.recv(257)
            # Current owner sends one bounded ASCII UUID, without a delimiter.
            lease_id = raw.decode('ascii')
            if not 1 <= len(raw) <= 128 or not all(
                    c.isascii() and (c.isalnum() or c in '-_.:') for c in lease_id):
                raise ValueError('invalid lifetime lease identifier')
            with self.lock:
                stored = self.handles.get(lease_id)
                token = object()
                self.lifetime_pending[lease_id] = token
                incarnation = self.identity
                if not self.lifetime_eligible(lease_id, stored):
                    raise ValueError('lifetime lease unavailable')
            # Never replace the old socket until the acknowledgement was sent.
            connection.sendall(b'ok')
            connection.settimeout(None)
            with self.lock:
                if (incarnation != self.identity
                        or self.lifetime_pending.get(lease_id) is not token
                        or not self.lifetime_eligible(lease_id, stored)):
                    raise ValueError('lifetime lease changed during acknowledgement')
                # A peer that disconnected during send must not replace a healthy watcher.
                connection.setblocking(False)
                try:
                    peer = connection.recv(1, socket.MSG_PEEK)
                except BlockingIOError:
                    peer = None
                finally:
                    connection.setblocking(True)
                if peer is not None:
                    raise ValueError('lifetime peer disconnected or sent unexpected data')
                previous = self.lifetimes.get(lease_id)
                self.lifetimes[lease_id] = connection
                installed = True
            if previous is not None:
                previous.close()
        finally:
            with self.lock:
                if token is not None and self.lifetime_pending.get(lease_id) is token:
                    self.lifetime_pending.pop(lease_id, None)
            if not installed:
                connection.close()

    def drop_lifetime(self, lease_id):
        with self.lock:
            # A drop with no installed entry still revokes in-flight handshakes.
            self.lifetime_pending.pop(lease_id, None)
            connection = self.lifetimes.pop(lease_id, None)
        if connection is not None:
            connection.close()
