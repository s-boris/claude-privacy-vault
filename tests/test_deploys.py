#!/usr/bin/python3 -I
"""Telegram-approved deploys (app/deploys.py): the request file, the card from the runner's review, the owner's
✅/❌ (his message, the single-use nonce), the approval file bound to the review's sha256, results, expiry, restart,
hostile runner files, the bot routing and that no API route approves. No network: a fake notifier and temp dirs
stand in for Telegram and the host's deploy mailbox."""
import hashlib
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'app'))
TMP = Path(tempfile.mkdtemp(prefix='vault-deploys-tests-'))

import deploys as D  # noqa: E402
import vaultlib as V  # noqa: E402

C1, C2, C3 = 'a' * 40, 'b' * 40, 'c' * 40
T0 = 1_800_000_000


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


class FakeNotifier:
    def __init__(self):
        self.sent, self.edits, self.answers, self.fail = [], [], [], False

    def send(self, text, buttons=None, html=False, silent=False):
        if self.fail:
            raise V.NotifyError('Telegram sendMessage failed: test')
        self.sent.append((text, buttons))
        return 500 + len(self.sent)

    def edit(self, message_id, text):
        self.edits.append((message_id, text))

    def answer(self, callback_id, text):
        self.answers.append(text)

    def chat_id(self):
        return '42'

    def bot_id(self):
        return 7


class Approver:
    ok = True

    def healthy(self):
        return self.ok


def review_text(rid, commit, running=C1, kind='update', commits=2, weights='same', privacy='same', build='same',
                settings='-', telegram='yes', allowed='yes', why='-', subject='app: a change',
                files=(('!', 'M', 'app/x.py'),), total=None):
    """What vault-deploy-runner.sh writes (results/ID.review); total = all changed files (default: the listed ones)."""
    lines = ['claude-vault-deploy-review 1', f'id {rid}', f'commit {commit}', f'running {running}', f'kind {kind}',
             f'commits {commits}', f'weights {weights}', f'privacy {privacy}', f'build {build}', f'settings {settings}',
             f'telegram {telegram}', f'allowed {allowed}', f'why {why}', 'date 2026-01-02 03:04', f'subject {subject}',
             'stat 1 file changed, 2 insertions(+)', f'files {len(files) if total is None else total}',
             f"flagged {sum(m == '!!' for m, _, _ in files)}", f"code {sum(m == '!' for m, _, _ in files)}"]
    lines += [f'file {m} {s} {p}' for m, s, p in files] + ['end']
    return ('\n'.join(lines) + '\n').encode()


def result_text(rid, commit, outcome='deployed', step='deploy', reason='the new vault answers /health'):
    return (f'claude-vault-deploy-result 1\nid {rid}\ncommit {commit}\nstep {step}\noutcome {outcome}\n'
            f'reason {reason}\nfinished {T0}\nrunning {commit}\n').encode()


class Base(unittest.TestCase):
    def setUp(self):
        d = TMP / self._testMethodName
        self.req, self.res = d / 'requests', d / 'results'
        self.req.mkdir(parents=True)
        self.res.mkdir(parents=True)
        self.cfg = V.Config({'VAULT_DATA': str(d / 'data'), 'VAULT_DEPLOY_REQUESTS': str(self.req),
                             'VAULT_DEPLOY_RESULTS': str(self.res)})
        self.audit = V.Audit(self.cfg.audit_path)
        self.n, self.clock, self.approver = FakeNotifier(), Clock(), Approver()
        self.alive()
        self.d = self.make()

    def make(self):
        return D.Deploys(self.cfg, self.n, self.audit, approver=self.approver, clock=self.clock, log=lambda *a: None)

    def alive(self, seen=None, state='idle', job=None):
        seen = self.clock.t if seen is None else seen
        (self.res / 'alive').write_text(f'claude-vault-deploy-runner 1\nseen {seen}\n')
        (self.res / 'runner').write_text(f'claude-vault-deploy-runner 1\nstate {state}\n' + (f'job {job} {seen}\n' if job else '')
                                         + f'deployed {C1}\nseen {seen}\n')

    def put(self, name, data):
        (self.res / name).write_bytes(data)

    def to_card(self, commit=C2, **kw):
        """request -> the runner's review -> tick: the card is out. -> (rid, review bytes, callback data)"""
        rid = self.d.request(commit)['request_id']
        data = review_text(rid, commit, **kw)
        self.put(f'{rid}.review', data)
        self.d.tick()
        text, buttons = self.n.sent[-1]
        return rid, data, buttons

    def tap(self, data, message_id=None):
        return self.d.on_callback({'id': 'cq1', 'data': data,
                                   'message': {'message_id': message_id or 500 + len(self.n.sent)}})

    def audit_events(self):
        return [e['event'] for e in self.audit.read(days=1)]


class RequestTests(Base):
    def test_request_writes_the_review_file(self):
        r = self.d.request(C2.upper())
        rid = r['request_id']
        self.assertEqual((r['state'], r['commit']), ('reviewing', C2))
        self.assertRegex(rid, r'^[0-9a-f]{32}$')
        p = self.req / f'{rid}.review'
        self.assertEqual(p.read_text(), f'claude-vault-deploy-request 1\nid {rid}\nstep review\ncommit {C2}\n'
                                        f'created {T0}\n')
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        self.assertEqual([x.name for x in self.req.iterdir()], [p.name])      # no temp file left
        self.assertEqual(self.n.sent, [])                                      # nothing to the owner yet
        self.assertIn('deploy_request', self.audit_events())

    def test_refusals(self):
        for bad in ('abc1234', C2[:39], C2 + 'a', 'g' * 40, '', None, C2 + 'x', f'{C2} {C3}'):
            with self.assertRaises(V.VaultError) as e:
                self.d.request(bad)
            self.assertEqual(e.exception.code, 'bad_param', bad)
        self.approver.ok = False
        with self.assertRaises(V.VaultError) as e:
            self.d.request(C2)
        self.assertEqual(e.exception.code, 'no_buttons')
        self.approver.ok = True
        self.alive(seen=T0 - 600)
        with self.assertRaises(V.VaultError) as e:
            self.d.request(C2)
        self.assertEqual(e.exception.code, 'runner_down')
        (self.res / 'alive').unlink()
        with self.assertRaises(V.VaultError) as e:
            self.d.request(C2)
        self.assertEqual(e.exception.code, 'runner_down')
        self.alive(state='paused')
        with self.assertRaises(V.VaultError) as e:
            self.d.request(C2)
        self.assertEqual(e.exception.code, 'runner_paused')
        self.alive()
        self.req.rmdir()
        with self.assertRaises(V.VaultError) as e:
            self.d.request(C2)
        self.assertEqual(e.exception.code, 'mailbox')

    def test_a_newer_request_replaces_a_waiting_one_but_not_a_running_deploy(self):
        rid1, _, buttons = self.to_card()
        rid2 = self.d.request(C3)['request_id']
        self.assertEqual(self.d.st['requests'][rid1]['state'], 'cancelled')
        self.assertFalse((self.req / f'{rid1}.review').exists())
        self.assertIn('Replaced by a newer request', self.n.edits[-1][1])
        self.assertEqual(self.tap(buttons[0][0][1], message_id=501), 'Already cancelled')
        self.put(f'{rid2}.review', review_text(rid2, C3))
        self.d.tick()
        self.tap(self.n.sent[-1][1][0][0][1])
        with self.assertRaises(V.VaultError) as e:
            self.d.request(C2)
        self.assertEqual(e.exception.code, 'busy')

    def test_daily_limit(self):
        for _ in range(D.Deploys.MAX_PER_DAY):
            self.d.request(C2)
        with self.assertRaises(V.VaultError) as e:
            self.d.request(C2)
        self.assertEqual(e.exception.code, 'daily_limit')
        self.clock.t += 86400
        self.alive()
        self.d.request(C2)


class CardTests(Base):
    def test_card_from_the_runners_facts(self):
        rid, data, buttons = self.to_card(kind='rollback', commits=3, weights='changed', privacy='changed',
                                          build='changed', subject='undo ‮gnp.exe the change',
                                          files=(('!!', 'M', 'vendor/llm-local'), ('-', 'A', 'docs/x.md')))
        text = self.n.sent[-1][0]
        self.assertTrue(text.startswith(f'⏪ ROLLBACK the vault to {C2[:7]}?\n“undo gnp.exe the change” (2026-01-02 03:04)\n'
                                        f'ROLLBACK: 3 commits back from {C1[:7]} (running now)'), text)
        for s in ('WEIGHTS CHANGED', 'Privacy filter changed', 'Image build changed', '!! M vendor/llm-local',
                  '   A docs/x.md', 'Checked by your server: on GitHub main, container settings unchanged'):
            self.assertIn(s, text)
        self.assertNotIn('‮', text)                                     # no bidi tricks on the card
        r = self.d.st['requests'][rid]
        self.assertEqual(r['state'], 'awaiting')
        self.assertEqual(r['review_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(buttons, [[('✅ Deploy', f"D:a:{rid}:{r['nonce']}"), ('❌ Cancel', f"D:d:{rid}:{r['nonce']}")]])
        self.assertTrue(all(len(b[1].encode()) <= 64 for b in buttons[0]))   # Telegram's callback_data limit
        self.assertIn('deploy_card', self.audit_events())

    def test_update_card_and_many_files(self):
        files = tuple(('-', 'M', f'f{i}.txt') for i in range(20))
        rid = self.d.request(C2)['request_id']
        self.put(f'{rid}.review', review_text(rid, C2, files=files).replace(b'files 20', b'files 31'))
        self.d.tick()
        text = self.n.sent[-1][0]
        self.assertIn(f'2 new commits since {C1[:7]} (running now)', text)
        self.assertIn('… and 19 more', text)
        self.assertEqual(text.count('\n   M f'), 12)
        self.assertNotIn('!! privacy filter or container', text)                # no marks, no legend

    def test_settings_and_flagged_files_are_never_hidden(self):
        # 14 !! files after 6 plain ones (an older order): the card shows the !! files first and counts the hidden
        files = tuple(('-', 'A', f'a/f{i}.txt') for i in range(6)) + tuple(('!!', 'M', f'vendor/llm-local/p{i}')
                                                                           for i in range(14))
        rid = self.d.request(C2)['request_id']
        self.put(f'{rid}.review', review_text(rid, C2, files=files, total=40, settings='VAULT_INDEX,VAULT_PHOTOS'))
        self.d.tick()
        text = self.n.sent[-1][0]
        self.assertIn('⚙️ Settings changed (vault.env): VAULT_INDEX, VAULT_PHOTOS', text)
        listed = [l for l in text.split('\n') if l.startswith(('!! ', '!  ', '   '))]
        self.assertEqual(listed[:12], [f'!! M vendor/llm-local/p{i}' for i in range(12)])
        self.assertIn('… and 28 more (of them 2 !!)', text)
        self.assertIn('!! privacy filter or container · ! vault code', text)

    def test_not_allowed_no_card(self):
        rid = self.d.request(C2)['request_id']
        self.put(f'{rid}.review', review_text(rid, C2, allowed='no', why='container settings changed (docker-compose.yml)'))
        self.d.tick()
        r = self.d.status(rid)['request']
        self.assertEqual(r['state'], 'refused')
        self.assertIn('needs the User Scripts button: container settings changed', r['reason'])
        self.assertEqual(self.n.sent, [])                                      # nothing to the owner
        self.assertFalse((self.req / f'{rid}.review').exists())

    def test_review_refused_by_the_runner(self):
        rid = self.d.request(C2)['request_id']
        self.put(f'{rid}.result', result_text(rid, C2, 'refused', 'review', 'the commit is not on GitHub main'))
        self.d.tick()
        self.assertEqual(self.d.status(rid)['request']['reason'], 'the commit is not on GitHub main')
        self.assertEqual(self.n.sent, [])

    def test_hostile_or_broken_reviews(self):
        rid = self.d.request(C2)['request_id']
        good = review_text(rid, C2)
        bad = [good.replace(b'kind update', b'kind evil'), good.replace(b'\nend\n', b'\n'),
               good.replace(b'weights same', b'weights maybe'), good.replace(b'commits 2', b'commits -2'),
               good.replace(b'running ' + C1.encode(), b'running $(id)'),
               good.replace(b'end\n', b''.join(b'file - M x\n' for _ in range(26)) + b'end\n'),
               good.replace(b'file ! M', b'file !!! M'), review_text(rid, C3), review_text('f' * 32, C2),
               good.replace(b'settings -', b'settings LD_PRELOAD'), good.replace(b'settings -', b'settings VAULT_A;id'),
               good.replace(b'code 1', b'code 9'), good.replace(b'flagged 0\n', b'')]
        for i, data in enumerate(bad):
            with self.subTest(i=i):
                self.d.st['requests'][rid].update(state='reviewing', review=None)
                self.put(f'{rid}.review', data)
                self.d.tick()
                self.assertEqual(self.d.st['requests'][rid]['state'], 'failed')
        self.assertEqual(self.n.sent, [])

    def test_a_symlinked_or_odd_results_file_is_not_read(self):
        rid = self.d.request(C2)['request_id']
        elsewhere = self.res.parent / 'elsewhere'
        elsewhere.write_bytes(review_text(rid, C2))
        (self.res / f'{rid}.review').symlink_to(elsewhere)
        self.d.tick()
        self.assertEqual(self.d.st['requests'][rid]['state'], 'reviewing')
        (self.res / f'{rid}.review').unlink()
        os.mkfifo(self.res / f'{rid}.review')
        self.d.tick()                                                          # a FIFO: not waited on
        self.assertEqual(self.d.st['requests'][rid]['state'], 'reviewing')
        (self.res / f'{rid}.review').unlink()
        self.put(f'{rid}.review', b'x' * 20000)                               # oversized: not read either
        self.d.tick()
        self.assertEqual(self.d.st['requests'][rid]['state'], 'reviewing')


class TapTests(Base):
    def test_approve_writes_the_bound_approval_once(self):
        rid, data, buttons = self.to_card()
        ok, cancel = buttons[0][0][1], buttons[0][1][1]
        mid = 500 + len(self.n.sent)
        self.assertEqual(self.tap(ok, message_id=mid + 1), 'This button is not valid')         # another message
        self.assertEqual(self.tap(ok[:-1] + ('A' if ok[-1] != 'A' else 'B'), message_id=mid), 'This button is not valid')
        self.assertEqual(self.tap('D:a:' + 'f' * 32 + ':' + 'x' * 16, message_id=mid), 'This deploy request is gone')
        self.assertEqual(self.tap('D:z:junk'), 'Unknown button')
        self.assertFalse((self.req / f'{rid}.deploy').exists())
        self.clock.t += 60
        self.assertEqual(self.tap(ok, message_id=mid), 'Approved ✓ Your server deploys it within a minute')
        self.assertEqual((self.req / f'{rid}.deploy').read_text(),
                         f'claude-vault-deploy-request 1\nid {rid}\nstep deploy\ncommit {C2}\n'
                         f'review {hashlib.sha256(data).hexdigest()}\napproved {T0 + 60}\nexpires {T0 + 60 + 1800}\n')
        self.assertEqual(self.d.status(rid)['request']['state'], 'approved')
        self.assertIn('✅ Approved: your server deploys it within a minute', self.n.edits[-1][1])
        self.assertEqual(self.tap(ok, message_id=mid), 'Already approved')                     # single use
        self.assertEqual(self.tap(cancel, message_id=mid), 'Already approved')
        ev = self.audit_events()
        self.assertIn('deploy_approved', ev)
        self.assertEqual(ev.count('deploy_callback_refused'), 4)

    def test_cancel(self):
        rid, _, buttons = self.to_card()
        self.assertEqual(self.tap(buttons[0][1][1]), 'Cancelled ✓')
        self.assertEqual(self.d.status(rid)['request']['state'], 'denied')
        self.assertEqual(list(self.req.iterdir()), [])
        self.assertIn('❌ Cancelled', self.n.edits[-1][1])

    def test_mailbox_gone_at_the_tap(self):
        rid, _, buttons = self.to_card()
        (self.req / f'{rid}.review').unlink()
        self.req.rmdir()
        self.assertEqual(self.tap(buttons[0][0][1]), 'Could not hand it to your server')
        self.assertEqual(self.d.status(rid)['request']['state'], 'failed')
        self.assertIn('failed', self.n.sent[-1][0])

    def test_card_could_not_be_sent(self):
        rid = self.d.request(C2)['request_id']
        self.put(f'{rid}.review', review_text(rid, C2))
        self.n.fail = True
        self.d.tick()
        self.assertEqual(self.d.status(rid)['request']['state'], 'failed')


class ResultTests(Base):
    def approved(self):
        rid, data, buttons = self.to_card()
        self.tap(buttons[0][0][1])
        return rid

    def test_deployed(self):
        rid = self.approved()
        self.alive(state='busy', job=f'{rid} deploy')
        self.d.tick()
        self.assertEqual(self.d.status(rid)['request']['state'], 'deploying')
        self.put(f'{rid}.result', result_text(rid, C2))
        self.d.tick()
        self.assertEqual(self.d.status(rid)['request']['state'], 'deployed')
        self.assertEqual(self.n.sent[-1], (f'✅ Vault {C2[:7]} is deployed.', None))
        self.assertIn('✅ Deployed ·', self.n.edits[-1][1])
        self.assertEqual(list(self.req.iterdir()), [])
        n = len(self.n.sent)
        self.d.tick()
        self.assertEqual(len(self.n.sent), n)                                  # told once

    def test_failed_and_refused(self):
        for outcome, reason, start in (('failed', 'the tests failed: nothing changed, the old vault keeps running', '⚠️'),
                                       ('refused', 'the approval has expired', '⛔')):
            rid = self.approved()
            self.put(f'{rid}.result', result_text(rid, C2, outcome, reason=reason))
            self.d.tick()
            self.assertEqual(self.d.status(rid)['request']['state'], outcome)
            self.assertTrue(self.n.sent[-1][0].startswith(start) and self.n.sent[-1][0].endswith(reason))

    def test_a_result_survives_the_restart_the_deploy_causes(self):
        rid = self.approved()
        self.d = self.make()                                                   # the new vault after the switch
        self.put(f'{rid}.result', result_text(rid, C2))
        self.d.tick()
        self.assertEqual(self.d.status(rid)['request']['state'], 'deployed')
        self.assertEqual(self.n.sent[-1][0], f'✅ Vault {C2[:7]} is deployed.')

    def test_expiry(self):
        rid = self.d.request(C2)['request_id']
        self.clock.t += D.Deploys.REVIEW_WAIT + 1
        self.alive()
        self.d.tick()
        self.assertEqual(self.d.status(rid)['request']['state'], 'expired')
        self.assertEqual(self.n.sent, [])
        rid, _, buttons = self.to_card()
        self.clock.t += D.Deploys.CARD_TTL + 1
        self.d.tick()
        self.assertEqual(self.d.status(rid)['request']['state'], 'expired')
        self.assertIn('⌛ Expired: not decided within 12 h', self.n.edits[-1][1])
        self.assertEqual(self.tap(buttons[0][0][1], message_id=self.d.st['requests'][rid]['message_id']), 'Already expired')
        self.alive()
        rid = self.approved()
        self.clock.t += D.Deploys.APPROVAL_TTL + 121
        self.d.tick()
        self.assertEqual(self.d.status(rid)['request']['state'], 'expired')
        self.assertIn('did not start it within 30 min', self.n.sent[-1][0])
        self.assertFalse((self.req / f'{rid}.deploy').exists())               # no late deploy
        self.alive()
        rid = self.approved()
        self.alive(state='busy', job=f'{rid} deploy')
        self.clock.t += D.Deploys.DEPLOY_WAIT + 1
        self.d.tick()
        self.assertEqual(self.d.status(rid)['request']['state'], 'failed')
        self.assertIn('no result from your server after 3 h', self.n.sent[-1][0])

    def test_status_and_cleanup(self):
        rid = self.approved()
        (self.req / ('e' * 32 + '.review')).write_text('stale')
        (self.req / '.x.tmp').write_text('stale')
        self.d = self.make()
        self.d.cleanup()
        self.assertEqual(sorted(p.name for p in self.req.iterdir()), [f'{rid}.deploy', f'{rid}.review'])
        s = self.d.status()
        self.assertTrue(s['runner']['alive'])
        self.assertEqual(s['runner']['deployed'], C1)
        self.assertEqual(s['requests'][0]['request_id'], rid)
        self.assertEqual(self.d.status(rid[:8])['request']['state'], 'approved')
        with self.assertRaises(V.VaultError):
            self.d.status('zz')
        self.assertNotIn('nonce', json.dumps(s))
        self.assertEqual(json.loads(self.d.path.read_text())['requests'][rid]['state'], 'approved')
        self.assertEqual(self.d.path.stat().st_mode & 0o777, 0o600)


class WiringTests(Base):
    def test_bot_routes_deploy_buttons_only_from_the_owner(self):
        cfg = V.Config({'VAULT_DATA': str(TMP / 'bot'), 'VAULT_TEST_MODE': '1'})
        bot = V.ApprovalBot(cfg, None, self.n, self.audit, log=lambda *a: None)
        bot.deploys = self.d
        rid, _, buttons = self.to_card()
        mid = 500 + len(self.n.sent)
        cq = {'id': 'q', 'data': buttons[0][0][1], 'from': {'id': 99}, 'message': {'message_id': mid, 'chat': {'id': 42}}}
        bot.handle(cq)
        self.assertEqual(self.d.st['requests'][rid]['state'], 'awaiting')       # not his: ignored
        self.assertIn('raw_callback_refused', self.audit_events())
        cq['from']['id'] = 42
        bot.handle(cq)
        self.assertEqual(self.d.st['requests'][rid]['state'], 'approved')
        self.assertEqual(self.n.answers[-1], 'Approved ✓ Your server deploys it within a minute')

    def test_no_api_route_approves_a_deploy(self):
        src = (ROOT / 'app' / 'vaultd.py').read_text()
        routes = re.findall(r"\('(GET|POST|PUT|DELETE)', '(/deploy[^']*)'\)", src)
        self.assertEqual(sorted(routes), [('GET', '/deploy/status'), ('POST', '/deploy/request')])
        self.assertEqual(re.findall(r'deploys\.(\w+)\(', src), ['request', 'status'])
        lib = (ROOT / 'app' / 'deploys.py').read_text()
        self.assertEqual(lib.count("step deploy"), 1)                          # the approval is written in one place
        self.assertLess(lib.index('def on_callback'), lib.index("step deploy"))

    @unittest.skipUnless((ROOT / 'docker-compose.yml').is_file() and (ROOT / 'vault.env').is_file(),
                         'compose files not here (image)')
    def test_compose_keeps_settings_out_of_the_privileged_file(self):
        comp = (ROOT / 'docker-compose.yml').read_text()
        self.assertIn('env_file: [vault.env, .env]', comp)                   # this server's .env wins
        self.assertIn('user: "10001:10001"', comp)
        self.assertIn('/requests:/deploy/requests\n', comp)
        self.assertIn('/results:/deploy/results:ro\n', comp)
        self.assertNotIn('environment:', comp)
        for line in (ROOT / 'vault.env').read_text().splitlines():
            self.assertRegex(line, r'^(#.*)?$|^VAULT_[A-Z0-9_]+=[A-Za-z0-9_.,:/@+=-]*$')


if __name__ == '__main__':
    unittest.main(verbosity=1)
