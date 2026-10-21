{lib}: let
  pattern = "(http|https)://([a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?)(:([1-9][0-9]{0,4}))?";
in {
  type = lib.types.addCheck (lib.types.strMatching pattern) (url: let
    parts = builtins.match pattern url;
    port = builtins.elemAt parts 4;
  in
    (port == null || lib.toInt port <= 65535)
    && builtins.all (label: builtins.match "[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?" label != null)
    (lib.splitString "." (builtins.elemAt parts 1)));
  parse = url: let
    parts =
      if url == null
      then null
      else builtins.match pattern url;
    secure = parts != null && builtins.elemAt parts 0 == "https";
  in {
    url =
      if url == null
      then ""
      else url;
    host =
      if parts == null
      then ""
      else builtins.elemAt parts 1;
    inherit secure;
    scheme =
      if secure
      then "https"
      else "http";
    port =
      if parts == null || builtins.elemAt parts 4 == null
      then
        (
          if secure
          then 443
          else 80
        )
      else lib.toInt (builtins.elemAt parts 4);
  };
}
