"""Per-connection lifetime admission; no failure here stops the business bridge."""
import logging
from pathlib import Path
import socket
import stat

LOG = logging.getLogger(__name__)


class LifetimeListener:
    def init_lifetimes(self, capacity):
        self.lifetime_capacity = capacity
        self.lifetimes = {}
        self.lifetime_pending = {}
        self.lifetime_healthy = False
        self.lifetime_endpoint = None
        self.lifetime_inode = None
        self.lifetime_socket = self.new_lifetime_listener()

    def lifetime_endpoint_identity(self):
        entry = Path(self.lifetime_path).lstat()
        if not stat.S_ISSOCK(entry.st_mode):
            raise OSError('lifetime endpoint is not a socket')
        return (entry.st_dev, entry.st_ino)

    def unlink_lifetime_endpoint(self, endpoint):
        # A pathname is only a lookup: never acquire ownership during cleanup.
        if endpoint is None or self.lifetime_endpoint_identity() != endpoint:
            raise OSError('lifetime endpoint replaced; unlink refused')
        Path(self.lifetime_path).unlink()
        self.lifetime_endpoint = None
        self.lifetime_inode = None

    def new_lifetime_listener(self):
        self.lifetime_healthy = False
        listener = socket.socket(socket.AF_UNIX)
        bound_endpoint = None
        try:
            listener.bind(self.lifetime_path)
            # Once bind succeeded, absence is no longer an authorized rebind.
            # If identity acquisition fails, keep a non-owned refusal sentinel.
            self.lifetime_endpoint = ()
            self.lifetime_inode = None
            bound_endpoint = self.lifetime_endpoint_identity()
            self.lifetime_endpoint = bound_endpoint
            self.lifetime_inode = bound_endpoint[1]
            listener.listen(self.lifetime_capacity)
            listener.settimeout(.2)
            if self.lifetime_endpoint_identity() != bound_endpoint:
                raise OSError('lifetime endpoint changed before publication')
            self.lifetime_healthy = True
            return listener
        except BaseException:
            self.lifetime_healthy = False
            listener.close()
            if bound_endpoint is not None:
                try:
                    self.unlink_lifetime_endpoint(bound_endpoint)
                except OSError:
                    # A changed/missing/unreadable path is not authority to
                    # rebind later. Retain the original identity and refuse.
                    LOG.exception('lifetime creation cleanup refused; endpoint retained')
            raise

    def close_lifetime_listener(self):
        self.lifetime_healthy = False
        self.lifetime_socket.close()
        if self.lifetime_endpoint is None:
            return
        try:
            self.unlink_lifetime_endpoint(self.lifetime_endpoint)
        except FileNotFoundError:
            pass
        except OSError:
            LOG.exception('lifetime close cleanup refused; endpoint retained')

    def recover_lifetime_listener(self, failed):
        with self.lock:
            self.lifetime_healthy = False
            if self.stopped.is_set():
                return False
            try:
                if self.lifetime_socket is not failed:
                    if self.lifetime_endpoint_identity() != self.lifetime_endpoint:
                        raise OSError('current lifetime endpoint replaced; recovery refused')
                    self.lifetime_healthy = self.lifetime_socket.fileno() >= 0
                    return self.lifetime_healthy
                if self.lifetime_endpoint is not None:
                    if self.lifetime_endpoint_identity() != self.lifetime_endpoint:
                        raise OSError('lifetime endpoint replaced; recovery refused')
                    failed.close()
                    self.unlink_lifetime_endpoint(self.lifetime_endpoint)
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
                and not any(record.get('handle') is stored[1]
                            and (record.get('cancel_intent') or record.get('cancel_requested'))
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
