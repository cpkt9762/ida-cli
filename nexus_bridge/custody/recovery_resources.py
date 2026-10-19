"""Retained resource authority for file recovery; N1 remains session authority."""
import copy
import os
import time

from target_coordination import digest, encoded


class ResourceCustody:
    def require_resources(self, *, manual=False):
        permission=self.data.get('manual_offline_recovery')
        if permission is not None:
            self.validate_manual_permission(permission)
            from recovery_maintenance import occupancy
            self.owner_probe=lambda path:occupancy(permission['plan']['state_roots'],path)
            return
        if manual:
            raise RuntimeError('MaintenanceBlocked: no accepted offline permission')
        imported=self.data.get('imported_v1')
        if imported and imported.get('resources_unqualified'):
            raise RuntimeError('ObservationRecoveryBlocked: v1 has no complete original resource identity; explicit offline maintenance required')
        from target_journal import Journal
        journal = Journal(self.target)
        journal.recover_public_proofs()
        from target_journal import fact
        for requirement in sorted(self.data['requirements'],key=lambda item:item['epoch'],reverse=True):
            key = digest(requirement)
            certificate = self.data['certified_resources'].get(key)
            if certificate is not None:
                self.validate_certificate(requirement,certificate)
                continue
            item = journal.value['entries'].get(str(requirement['epoch']))
            fields = ('watch','epoch','acquisition','owner','lease','origin_binding')
            if item is None or any(item.get(k) != requirement.get(k) for k in fields):
                raise RuntimeError('RecoveryBlocked: exact resource evidence missing')
            if journal.retirement(item):
                evidence = {'scope':'verified_boot_change_resource_retirement',
                            'record':journal.retirement(item)}
            elif item.get('transferred_to') is not None:
                successor = next((r for r in self.data['requirements'] if r['epoch']==item['transferred_to']),None)
                if successor is None or digest(successor) not in self.data['certified_resources']:
                    raise RuntimeError('RecoveryBlocked: startup successor proof still pending')
                evidence = {'scope':'startup_transfer','successor':digest(successor),'record':copy.deepcopy(item)}
            elif item.get('launch'):
                raise RuntimeError('StartupUnconfirmed: recovery still has exact launch obligation')
            elif item.get('no_attach') or item.get('no_launch'):
                if not (item['producer_closed'] and item['consumer_closed'] and not item['unacked_events']):
                    raise RuntimeError('RecoveryBlocked: no-acquisition closure pending')
                evidence = {'scope':'no_acquisition','record':copy.deepcopy(item)}
            else:
                permission = item.get('file_recovery_ack',{})
                ack = item.get('detach_outcome',{})
                if permission.get('recovery_id') == self.recovery_id:
                    ack = permission['outcome']
                if not item.get('proof') or (item.get('lease') and
                        ack.get('lease_released') is not True):
                    raise RuntimeError('RecoveryBlocked: sameboot detach/public-owner double proof pending')
                # Verify the original immutable bytes before taking an
                # independent retained copy into this failed transaction.
                proof_record = journal.referenced_record(item['proof'])
                fact(dict(item['proof'],record=proof_record),self.target,kind='PublicOwnerLifetime')
                evidence = {'scope':'public_owner_lifetime','record':copy.deepcopy(item),
                            'proof_record':proof_record,'ack':ack}
            record = {'schema':1,'kind':'FileRecoveryResourceCustody','coord_key':self.target.key,
                      'target':self.target.original,'recovery_id':self.recovery_id,
                      'requirement':requirement,'evidence':evidence,'guard_epoch':self.token.epoch}
            name = 'resource-'+key+'.json'
            prior_intent = self.data['intent']
            if prior_intent and prior_intent.get('kind')=='resource_certificate' and prior_intent.get('name')==name:
                record = prior_intent['record']
            else:
                self.data['intent'] = {'kind':'resource_certificate','name':name,'record':record}
                self.save()
            self.directory.recover_record(name)
            try:
                stored, _, _ = self.directory.read(name)
            except FileNotFoundError:
                self.directory.durable(name,record,immutable=True)
            else:
                if encoded(stored) != encoded(record):
                    raise RuntimeError('RecoveryBlocked: retained resource certificate conflict')
            certificate = {'name':name,'sha256':digest(record)}
            self.data['certified_resources'][key] = certificate
            self.data['intent'] = None
            self.save()
            self.validate_certificate(requirement,certificate)

    def validate_manual_permission(self, permission):
        if (type(permission) is not dict or set(permission) != {'schema','plan_sha256','plan','applied_at'}
                or type(permission['schema']) is not int or permission['schema'] != 1
                or digest(permission['plan']) != permission['plan_sha256']):
            raise RuntimeError('MaintenanceBlocked: corrupt offline permission')
        plan=permission['plan']
        if (plan.get('kind') != 'manual_offline_recovery' or plan.get('target') != self.target.original
                or encoded(plan.get('coord_key')) != encoded(self.target.key)
                or plan.get('directory') != self.target.directory.identity
                or plan.get('transaction') != self.recovery_id
                or plan.get('operator',{}).get('uid') != os.getuid()
                or plan.get('operator',{}).get('confirmation') != 'I established and maintain this exclusive offline window'
                or not plan['window']['started_at'] <= permission['applied_at'] < plan['window']['expires_at']
                or not plan['window']['started_at'] <= time.time() < plan['window']['expires_at']):
            raise RuntimeError('MaintenanceBlocked: accepted offline window no longer valid')

    def validate_certificate(self, requirement, certificate):
        record, _, raw = self.directory.read(certificate['name'])
        if (certificate['name'] != 'resource-'+digest(requirement)+'.json'
                or digest(raw) != certificate['sha256']
                or type(record.get('schema')) is not int or record['schema'] != 1 or record.get('kind') != 'FileRecoveryResourceCustody'
                or encoded(record.get('coord_key')) != encoded(self.target.key)
                or record.get('target') != self.target.original or record.get('recovery_id') != self.recovery_id
                or encoded(record.get('requirement')) != encoded(requirement)):
            raise RuntimeError('RecoveryBlocked: retained file-resource custody binding mismatch')
        evidence = record['evidence']
        if evidence['scope']=='verified_boot_change_resource_retirement':
            from origin import boot_change, creation_scope
            original = evidence['record']
            expected = boot_change(requirement['origin_binding'],original.get('current'))
            expected.update(schema=1,watch=requirement['watch'],epoch=requirement['epoch'],
                acquisition=requirement['acquisition'],owner=requirement['owner'],lease=requirement['lease'],
                launch=original.get('launch'),coord_key=self.target.key,target_binding=self.target.binding)
            expected['sha256'] = digest(expected)
            if encoded(original) != encoded(expected):
                raise RuntimeError('RecoveryBlocked: retained resource retirement certificate changed')
            boot_change(requirement['origin_binding'],creation_scope(self.target.directory.path,'file-recovery-consumer'))
        elif evidence['scope']=='public_owner_lifetime':
            item = evidence['record']
            proof = item.get('proof',{})
            proof_record = evidence['proof_record']
            permission = item.get('file_recovery_ack',{})
            ack = permission.get('outcome') if permission.get('recovery_id') == self.recovery_id else item.get('detach_outcome')
            if (not proof or digest(proof_record) != proof['sha256']
                    or proof_record.get('evidence_type') != 'public_owner_lifetime'
                    or proof_record.get('owner') != requirement['owner']
                    or proof_record.get('watch') != requirement['watch']
                    or proof_record.get('acquisition') != requirement['acquisition']
                    or proof_record.get('subscription_epoch') != requirement['epoch']
                    or encoded(proof_record.get('coord_key')) != encoded(self.target.key)
                    or encoded(ack) != encoded(evidence['ack'])
                    or (requirement['lease'] is not None and (not ack or ack.get('lease_released') is not True))):
                raise RuntimeError('RecoveryBlocked: retained public double proof changed')
        elif evidence['scope']=='startup_transfer':
            successor = next((r for r in self.data['requirements'] if digest(r)==evidence['successor']),None)
            if successor is None or successor['epoch'] <= requirement['epoch']:
                raise RuntimeError('RecoveryBlocked: invalid retained startup successor')
            if evidence['successor'] not in self.data['certified_resources']:
                raise RuntimeError('RecoveryBlocked: retained startup successor missing')
            self.validate_certificate(successor,self.data['certified_resources'][evidence['successor']])
        elif evidence['scope']=='no_acquisition':
            item = evidence['record']
            if (requirement['lease'] is not None or not (item.get('no_attach') or item.get('no_launch'))
                    or not item['producer_closed'] or not item['consumer_closed'] or item['unacked_events']):
                raise RuntimeError('RecoveryBlocked: retained no-acquisition evidence changed')
        else:
            raise RuntimeError('RecoveryBlocked: unsupported file-resource evidence scope')

