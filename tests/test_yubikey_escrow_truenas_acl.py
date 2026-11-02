"""Synthetic, no-real-SSH TrueNAS escrow native ACL inventory contracts."""
from __future__ import annotations
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]/'scripts/workstation/inspect-yubikey-escrow-truenas-acl.py'
spec = importlib.util.spec_from_file_location('nabla_escrow_native_acl', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Contracts(unittest.TestCase):
    def test_check_never_ssh_or_reads_ciphertext(self):
        base=SimpleNamespace(check_mount=lambda:"EXPECTED_NFS_EXPORT_MOUNTED",
                             local_expected_filename=lambda directory:("SOURCE_UNIQUE_AGE_FOUND","private.age"),
                             LOCAL_SOURCE=Path("/mock"))
        with patch.object(m,'load_base',return_value=base), \
             patch.object(m,'query_acl') as query, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--check"]),0)
        query.assert_not_called()
        result=json.loads(out.getvalue())
        self.assertEqual(result["state"],"NOT_PROBED")
        self.assertFalse(result["archive_opened"])
        self.assertFalse(result["nfs4_acl_verified"])

    def test_explicit_acknowledgment_gate(self):
        with patch.object(m,'query_acl') as query, redirect_stderr(io.StringIO()):
            for cmd in ([],["--probe"],["--probe","--acknowledge","no"],
                        ["--check","--acknowledge",m.ACK]):
                with self.subTest(cmd=cmd),self.assertRaises(SystemExit) as exc:
                    m.main(cmd)
                self.assertEqual(exc.exception.code,2)
        query.assert_not_called()

    def test_probe_wrong_mount_does_not_access_truenas(self):
        base=SimpleNamespace(check_mount=lambda:"UNEXPECTED_NFS_EXPORT",
                             local_expected_filename=lambda root:("SOURCE_UNIQUE_AGE_FOUND","private.age"),
                             LOCAL_SOURCE=Path("/mock"))
        with patch.object(m,'load_base',return_value=base), \
             patch.object(m,'query_acl') as remote, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--probe","--acknowledge",m.ACK]),3)
        remote.assert_not_called()
        self.assertEqual(json.loads(out.getvalue())["state"],"NOT_PROBED")

    def test_filename_and_ssh_target_restriction(self):
        with patch.object(m.subprocess,"run") as runner:
            self.assertEqual(m.query_acl("evil@other-host","private.age")["state"],"SSH_ACL_UNAVAILABLE")
            self.assertEqual(m.query_acl(m.SSH_TARGET,"../../private.age")["state"],"SSH_ACL_UNAVAILABLE")
        runner.assert_not_called()

    def test_remote_probe_only_embeds_filename_on_ssh_stdin(self):
        response={"state":"ACL_NATIVE_REVIEW_REQUIRED", "acltype":"NFS4",
                  "trivial":False,"ace_count":2,
                  "potential_nonowner_read_allow_count":0}
        with patch.object(m.subprocess,"run",
                return_value=SimpleNamespace(returncode=0,stdout=json.dumps(response))) as runner:
            self.assertEqual(m.query_acl(m.SSH_TARGET,"private.age"),response)
        args=runner.call_args.args[0]
        self.assertNotIn("private.age",repr(args))
        self.assertIn("StrictHostKeyChecking=yes",args)
        self.assertIn("BatchMode=yes",args)
        self.assertEqual(args[-2:],["python3","-"])
        self.assertIn("private.age",runner.call_args.kwargs["input"])
        self.assertEqual(runner.call_args.kwargs["stderr"],subprocess.DEVNULL)

    def test_bad_or_private_remote_responses_fail_closed(self):
        bad=[
            "private/path/secret",
            json.dumps({"state":"ACL_NATIVE_REVIEW_REQUIRED"}),
            json.dumps({"state":"FAKE", "acltype":"NFS4","trivial":False,
                        "ace_count":1,"potential_nonowner_read_allow_count":0}),
            json.dumps({"state":"ACL_NATIVE_REVIEW_REQUIRED","acltype":"NFS4",
                        "trivial":False,"ace_count":True,"potential_nonowner_read_allow_count":0}),
        ]
        for output in bad:
            with self.subTest(output=output[:12]),patch.object(
                    m.subprocess,"run",
                    return_value=SimpleNamespace(returncode=0,stdout=output)):
                self.assertEqual(m.query_acl(m.SSH_TARGET,"private.age")["state"],
                                 "SSH_ACL_UNAVAILABLE")

    def test_remote_no_retry_on_failed_ssh(self):
        with patch.object(m.subprocess,"run",
             return_value=SimpleNamespace(returncode=255,stdout="")) as runner:
            self.assertEqual(m.query_acl(m.SSH_TARGET,"private.age")["state"],
                             "SSH_ACL_UNAVAILABLE")
        self.assertEqual(runner.call_count,1)

    def test_valid_probe_still_never_claims_acl_verified_or_restoration(self):
        base=SimpleNamespace(check_mount=lambda:"EXPECTED_NFS_EXPORT_MOUNTED",
                             local_expected_filename=lambda root:("SOURCE_UNIQUE_AGE_FOUND","private.age"),
                             LOCAL_SOURCE=Path("/mock"))
        record={"state":"ACL_POTENTIAL_NONOWNER_DATA_ALLOW", "acltype":"NFS4",
                "trivial":False,"ace_count":3,"potential_nonowner_read_allow_count":1}
        with patch.object(m,'load_base',return_value=base), \
             patch.object(m,'query_acl',return_value=record), \
             redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--probe","--acknowledge",m.ACK]),0)
        parsed=json.loads(out.getvalue())
        self.assertEqual(parsed["status"],"NO-GO")
        self.assertFalse(parsed["nfs4_acl_verified"])
        self.assertFalse(parsed["restore_verified"])
        self.assertFalse(parsed["remote_write_performed"])
        self.assertFalse(parsed["acl_entries_disclosed"])
        self.assertNotIn("private.age",out.getvalue())

    def test_inaccessible_acl_fails_closed_without_printing_private_data(self):
        base=SimpleNamespace(check_mount=lambda:"EXPECTED_NFS_EXPORT_MOUNTED",
                             local_expected_filename=lambda root:("SOURCE_UNIQUE_AGE_FOUND","private.age"),
                             LOCAL_SOURCE=Path("/mock"))
        with patch.object(m,'load_base',return_value=base), \
             patch.object(m,'query_acl',return_value={
                 "state":"ACL_READ_UNAVAILABLE","acltype":"UNKNOWN","trivial":None,
                 "ace_count":None,"potential_nonowner_read_allow_count":None,
             }),redirect_stdout(io.StringIO()) as out:
            self.assertEqual(m.main(["--probe","--acknowledge",m.ACK]),3)
        self.assertEqual(json.loads(out.getvalue())["status"],"NO-GO")
        self.assertNotIn("private.age",out.getvalue())

    def test_remote_real_python_with_synthetic_acl_fixtures(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            directory=root/"secret";directory.mkdir()
            (directory/"example.age").write_bytes(b"SYNTHETIC ONLY")
            binpath=root/"bin";binpath.mkdir()
            script=binpath/"midclt"
            script.write_text('#!/bin/sh\ncat "$ACL_FAKE_JSON"\n',encoding="utf-8")
            script.chmod(0o700)
            fake_data=root/"acl.json"
            code='EXPECTED_NAME = "example.age"\n' + m.REMOTE.replace(
                'Path("/mnt/cpool/backup/lab/secret")',f"Path({str(directory)!r})"
            )
            env={**os.environ,"PATH":str(binpath)+os.pathsep+os.environ.get("PATH",""),
                 "ACL_FAKE_JSON":str(fake_data)}
            def run(acl):
                fake_data.write_text(json.dumps(acl),encoding="utf-8")
                proc=subprocess.run([sys.executable,"-"],input=code,text=True,
                                    capture_output=True,env=env,timeout=5)
                self.assertEqual(proc.returncode,0,proc.stderr)
                result=json.loads(proc.stdout)
                self.assertNotIn("example.age",proc.stdout)
                self.assertNotIn(str(directory),proc.stdout)
                return result
            owner={"tag":"owner@","type":"ALLOW",
                   "perms":{"BASIC":"FULL_CONTROL"},"flags":{"BASIC":"NOINHERIT"}}
            acl={"path":str(directory/"example.age"),"acltype":"NFS4",
                 "trivial":False,"acl":[owner]}
            self.assertEqual(run(acl)["state"],"ACL_NATIVE_REVIEW_REQUIRED")
            acl["acl"].append({"tag":"everyone@","type":"ALLOW",
                               "perms":{"BASIC":"READ"},"flags":{"BASIC":"NOINHERIT"}})
            suspicious=run(acl)
            self.assertEqual(suspicious["state"],"ACL_POTENTIAL_NONOWNER_DATA_ALLOW")
            self.assertEqual(suspicious["potential_nonowner_read_allow_count"],1)
            acl["acl"][-1]["flags"]={"INHERIT_ONLY":True}
            self.assertEqual(run(acl)["potential_nonowner_read_allow_count"],0)

if __name__=='__main__':
    unittest.main()
