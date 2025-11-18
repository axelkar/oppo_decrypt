{
  lib,
  python3Packages,
}:
python3Packages.buildPythonApplication {
  pname = "oppo_decrypt";
  version = "0.1.0";
  pyproject = true;

  src = ./.;

  build-system = [ python3Packages.setuptools ];

  dependencies = with python3Packages; [
    docopt
    pycryptodomex
  ];

  meta = {
    description = "Oppo .ofp firmware decrypter and OnePlus .ops decrypter/encrypter";
    homepage = "https://github.com/axelkar/oppo_decrypt";
    license = lib.licenses.mit;
    mainProgram = "oppo_decrypt";
  };
}
