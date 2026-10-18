"""Formal installed single-resolution boundary; private HTTP and OS models."""
import dataclasses
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from ida_nexus import DatabaseHandle, DatabaseOpenOptions, NexusConnectionError
import ida_nexus.handle as sdk
import ida_nexus._resolver as resolver
from process_identity import identity
from r0_transport import Boundary

ROOT = Path(os.environ['R2_CASE_ROOT'])/'sdk'
ROOT.mkdir(mode=0o700)


def record(value):
    with Path(os.environ['R2_LEDGER']).open('a') as output:
        output.write(json.dumps(value)+'\n')
        output.flush()
        os.fsync(output.fileno())


class SingleResolution(unittest.TestCase):
    def test_public_single_resolution_without_attach(self):
        with Boundary(ROOT/'single') as boundary:
            seen = []
            outcome = DatabaseHandle.resolve_outcome(str(boundary.path),
                options=DatabaseOpenOptions(spawn=False),
                observer=lambda stage, value: seen.append((stage, value)))
            self.assertEqual([stage for stage, _ in seen], ['BeforeResolve','Resolved'])
            self.assertIs(outcome['instance'], seen[-1][1])
            self.assertIs(outcome['first_instance'], outcome['instance'])
            self.assertIsNone(outcome['cause'])
            self.assertIsNone(outcome['failure_kind'])
            self.assertEqual(outcome['recovery'], 'none')
            self.assertEqual(outcome['attempts'], [])
            self.assertEqual(outcome['unresolved_attempts'], [])
            self.assertIsNone(outcome['handle'])
            self.assertFalse(outcome['sdk_reconnect_used'])
            self.assertEqual(boundary.requests, [])

    def test_observer_order_cause_identity_and_immediate_stop(self):
        for stage in ('BeforeResolve','Resolved'):
            for origin in ('options','explicit'):
                for error_type in (ValueError,NexusConnectionError):
                    with self.subTest(stage=stage,origin=origin,error=error_type):
                        with Boundary(ROOT/f'{stage}-{origin}-{error_type.__name__}') as boundary:
                            cause=error_type('exact refusal')
                            events=[]
                            def callback(name):
                                def observe(actual,value):
                                    events.append((name,actual))
                                    if name==origin and actual==stage:
                                        raise cause
                                return observe
                            result=DatabaseHandle.resolve_outcome(str(boundary.path),
                                options=DatabaseOpenOptions(spawn=False,
                                    acquisition_observer=callback('options')),
                                observer=callback('explicit'))
                            self.assertIs(result['cause'],cause)
                            self.assertEqual(result['stage'],stage)
                            self.assertEqual(events[-1],(origin,stage))
                            self.assertEqual(events.count(('options','BeforeResolve')),1)
                            self.assertEqual(result['attempts'],[])
                            self.assertFalse(result['sdk_reconnect_used'])
                            self.assertEqual(boundary.requests,[])
                            self.assertEqual(result['instance'] is not None,stage=='Resolved')

    def test_probe_failure_and_resolver_parameter_failure_never_attach(self):
        error=RuntimeError('exact probe cause')
        with patch.object(sdk,'probe_database_state',side_effect=error), \
                patch.object(sdk,'resolve_instance') as resolve:
            result=DatabaseHandle.resolve_outcome(str(ROOT/'missing.i64'))
        resolve.assert_not_called()
        self.assertIs(result['cause'],error)
        self.assertIsNone(result['recovery'])
        with Boundary(ROOT/'bad-timeout') as boundary:
            for timeout in (0,-1,float('nan')):
                with self.assertRaises(ValueError), patch.object(sdk,'resolve_instance') as resolve:
                    DatabaseHandle.resolve_outcome(str(boundary.path),
                        options=DatabaseOpenOptions(startup_timeout=timeout))
                resolve.assert_not_called()
                self.assertEqual(boundary.requests,[])

    def test_all_options_forward_and_recovery_propagates(self):
        options=DatabaseOpenOptions()
        fields={field.name for field in dataclasses.fields(options)}
        for state,packed,new,expected in (
            ('packed',True,False,'none'),('crashed',True,False,'restored'),
            ('crashed',False,False,'repaired'),('crashed',True,True,'none')):
            options=dataclasses.replace(options,new_database=new)
            instance=object()
            def resolve(path,**kwargs):
                self.assertEqual(path,'input')
                mapping={'startup_timeout':'timeout'}
                excluded={'keepalive','idle_timeout'}
                for name in fields-excluded-{'acquisition_observer'}:
                    self.assertEqual(kwargs[mapping.get(name,name)],getattr(options,name),name)
                self.assertTrue(callable(kwargs['acquisition_observer']))
                return instance
            with patch.object(sdk,'probe_database_state',return_value={
                    'state':state,'packed_database_exists':packed}), \
                    patch.object(sdk,'resolve_instance',side_effect=resolve) as calls:
                result=DatabaseHandle.resolve_outcome('input',options=options)
            self.assertIsNone(result['cause'])
            self.assertIs(result['instance'],instance)
            self.assertEqual(result['recovery'],expected)
            self.assertEqual(calls.call_count,1)

    def test_final_attach_has_no_hidden_resolve_on_503_or_unknown(self):
        for scenario in ('reject','attach-eof'):
            with Boundary(ROOT/('attach-'+scenario),scenario) as boundary:
                if scenario=='attach-eof':
                    original=boundary.server.RequestHandlerClass.do_GET
                    def no_ack(handler):
                        if 'sse=' in handler.path:
                            import socket
                            boundary.requests.append({'endpoint':'attach_eof'})
                            handler.connection.shutdown(socket.SHUT_RDWR)
                            handler.close_connection=True
                        else:
                            original(handler)
                    boundary.server.RequestHandlerClass.do_GET=no_ack
                result=DatabaseHandle.resolve_outcome(str(boundary.path),
                    options=DatabaseOpenOptions(spawn=False))
                self.assertIsNone(result['cause'])
                with patch.object(sdk,'resolve_instance',side_effect=AssertionError('no second resolve')):
                    attached=DatabaseHandle.attach_outcome(result['instance'],path=str(boundary.path),
                        recovery=result['recovery'])
                handle=attached['handle']
                self.assertIsNone(handle)
                self.assertEqual(attached['failure_kind'],
                    'lease_absent' if scenario=='reject' else 'unknown_attach')
                self.assertEqual(len(attached['unresolved_attempts']),
                    0 if scenario=='reject' else 1)
                self.assertEqual(len(attached['attempts']),1)
                self.assertFalse(attached['sdk_reconnect_used'])

    def test_actual_popen_and_ready_facts_survive_callback_rejection(self):
        # The native child is real; ready/HTTP are modeled. Real IDA readiness
        # is separately exercised by the installed SDK product probe.
        executable=ROOT/'native-child'
        executable.write_text('#!/bin/sh\nexec /bin/sleep 0.1\n')
        executable.chmod(0o700)
        for stage in ('Spawned','LogReady','Ready',None):
            with self.subTest(stage=stage), Boundary(ROOT/('ready-'+str(stage))) as boundary:
                source=ROOT/('source-'+str(stage))
                source.write_bytes(b'private input')
                children=[]
                failure=NexusConnectionError('exact ready refusal')
                def observer(actual,value):
                    if actual=='LaunchIntent':
                        record({'kind':'intent','source':'r2-sdk','suffix':value['suffix'],
                                'target':str(source),'executable':str(executable)})
                    if actual=='Spawned':
                        children.append(value['process'])
                        record({'kind':'started','source':'r2-sdk','suffix':value['suffix'],
                                'pid':value['pid'],'identity':identity(value['pid'])})
                    if actual==stage:
                        raise failure
                try:
                    with patch.object(resolver,'_find_console_script',return_value=str(executable)), \
                            patch.object(resolver,'_await_ready',return_value=boundary.instance):
                        result=DatabaseHandle.resolve_outcome(str(source),
                            options=DatabaseOpenOptions(startup_timeout=2),observer=observer)
                    self.assertEqual(len(children),1)
                    launches=dict(result['launches'])
                    self.assertIs(launches['Spawned']['process'],children[0])
                    self.assertEqual(result['attempts'],[])
                    self.assertIsNone(result['handle'])
                    self.assertEqual(boundary.requests,[])
                    self.assertFalse(result['sdk_reconnect_used'])
                    if stage:
                        self.assertIs(result['cause'],failure)
                        self.assertEqual(result['stage'],stage)
                    else:
                        self.assertIsNone(result['cause'])
                        self.assertEqual(result['stage'],'Resolved')
                    if stage in ('Ready',None):
                        self.assertIs(result['instance'],launches['Ready']['instance'])
                        self.assertIs(result['first_instance'],result['instance'])
                finally:
                    for child in children:
                        status=child.wait(timeout=3)
                        record({'kind':'reaped','source':'r2-sdk','pid':child.pid,'exit':status})
                        self.assertEqual(status,0)


if __name__=='__main__':
    unittest.main(verbosity=2)
