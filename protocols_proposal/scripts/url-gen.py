import urllib.parse, sys

msg="Usage: python3 url-gen.py [lean | dot] file > file.url"

if len(sys.argv) == 3:
    file_name = sys.argv[2]
    choice = sys.argv[1]
    try:
        code = open(file_name).read()
        parsed_code = urllib.parse.quote(code)
    except Exception as e:
        print(f"Couldn't open or parse: {file_name}", file=sys.stderr)             
        print(e,file=sys.stderr)
        exit(1)
    if choice == "lean":
        print('https://live.lean-lang.org/#code=' + parsed_code)
    elif choice == "dot":
        print('https://dreampuf.github.io/GraphvizOnline/?engine=fdp#' + parsed_code)
    else:
        print(f"Wrong choice: {choice}\n{msg}", file=sys.stderr)
        exit(1)
    print(f"URL-encoding for {file_name} successfully generated.", file=sys.stderr)
    exit(0)

print(f"Input error: {msg}", file=sys.stderr)