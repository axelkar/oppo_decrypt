import sys
from pathlib import Path

import frida


def on_message(message, data):
    if message["payload"] == "Output":
        path = Path("test.data")
        if path.exists():
            path.remove()
        with path.open("wb") as wf:
            wf.write(data)
    else:
        print("Message: {message}")
        # print(f"[{message}] => {data}")


def main(target_process):
    pid = frida.spawn([target_process])
    session = frida.attach(pid)
    script = session.create_script("""
    lang = Module.findExportByName("kernel32", "GetSystemDefaultLCID");

    Interceptor.attach(lang, {
        onEnter: function (args) {
            console.log('Found backdoor function');
        },

        // When function is finished
        onLeave: function (retval) {
            retval=0x804;
            console.log('Press F8 to enable read backdoor, Password: oneplus');
            return retval;
        }
    });
""")
    script.on("message", on_message)
    script.load()
    frida.resume(pid)
    print(
        "[!] Ctrl+D on UNIX, Ctrl+C on Windows/cmd.exe to detach from instrumented program.\n\n"
    )
    sys.stdin.read()
    session.detach()


def cli_main(argv=sys.argv):
    if len(argv) != 2:
        print("Oppo MSMDownloadTool V4.0 Backdoor enabler (c) B.Kerler 2022\n")
        print("Usage: backdoor <process name or PID>")
        return 1

    try:
        target_process = int(argv[1])
    except ValueError:
        target_process = argv[1]
    main(target_process)


if __name__ == "__main__":
    sys.exit(cli_main())
