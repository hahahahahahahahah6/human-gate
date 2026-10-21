"""Best-effort cross-platform desktop notifications. Never raises."""
from __future__ import annotations

import platform
import shutil
import subprocess


def notify(title: str, body: str) -> bool:
    """Show a desktop notification. Returns True if a notifier ran, else False."""
    try:
        system = platform.system()
        if system == "Darwin":
            if shutil.which("osascript"):
                script = f'display notification "{_esc(body)}" with title "{_esc(title)}"'
                subprocess.run(["osascript", "-e", script],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=10)
                return True
        elif system == "Windows":
            ps = (
                "[Windows.UI.Notifications.ToastNotificationManager, "
                "Windows.UI.Notifications, ContentType=WindowsRuntime] > $null; "
                "$t = [Windows.UI.Notifications.ToastNotificationManager]::"
                "GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::"
                "ToastText02); "
                f"$t.GetElementsByTagName('text')[0].AppendChild($t.CreateTextNode('{_ps_esc(title)}')) > $null; "
                f"$t.GetElementsByTagName('text')[1].AppendChild($t.CreateTextNode('{_ps_esc(body)}')) > $null; "
                "[Windows.UI.Notifications.ToastNotificationManager]::"
                "CreateToastNotifier('human-gate').Show($t)"
            )
            subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=15)
            return True
        else:  # Linux and friends
            if shutil.which("notify-send"):
                subprocess.run(["notify-send", title, body, "--app-name=human-gate"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=10)
                return True
    except Exception:
        pass
    return False


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _ps_esc(s: str) -> str:
    return s.replace("'", "''")
