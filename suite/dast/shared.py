"""Small helpers shared by the dynamic scanners."""
import shutil
import subprocess


def tool_available(tool):
    return shutil.which(tool) is not None


def run_tool(cmd, timeout=1800, ok_codes=(0,), env=None, cwd=None, stdin=None):
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd, input=stdin)
    if ok_codes is not None and out.returncode not in ok_codes:
        raise RuntimeError("%s exited %d: %s" % (cmd[0], out.returncode, (out.stderr or out.stdout)[-1500:]))
    return out
