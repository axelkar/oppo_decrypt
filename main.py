import importlib
import os
import sys

is_windows = os.name == "nt"
can_debug_msmdownloadtool = is_windows and (
    importlib.util.find_spec("frida") is not None
)


def main(argv=sys.argv):
    tool = argv[1] if len(argv) > 1 else None

    if tool == "backdoor" and can_debug_msmdownloadtool:
        from .backdoor import cli_main

        return cli_main(argv[1:])
    elif tool == "ofp_mtk_decrypt":
        from .ofp_mtk_decrypt import cli_main

        return cli_main(argv[1:])
    elif tool == "ofp_qc_decrypt":
        from .ofp_qc_decrypt import cli_main

        return cli_main(argv[1:])
    elif tool == "ops_decrypt_frida" and can_debug_msmdownloadtool:
        from .ops_decrypt_frida import cli_main

        return cli_main(argv[1:])
    elif tool == "opscrypto":
        from .opscrypto import main

        return main(argv[1:])
    else:
        return f"Usage: oppo_decrypt <{'backdoor|' if can_debug_msmdownloadtool else ''}ofp_mtk_decrypt|ofp_qc_decrypt{'|ops_decrypt_frida' if can_debug_msmdownloadtool else ''}|opscrypto> [tool arguments]"


if __name__ == "__main__":
    sys.exit(main())
