import argparse

from app.local_scan import scan_local_folder


def main() -> None:
    parser = argparse.ArgumentParser(prog="agentsupplyshield")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan-local", help="Scan one local folder.")
    scan_parser.add_argument("path", help="Local folder to scan.")
    scan_parser.add_argument("--output-dir", required=True, help="Directory for JSON and Markdown reports.")
    scan_parser.add_argument(
        "--artifact-store-dir",
        help="Directory for separated raw_artifacts and parsed_artifacts output. Defaults to output-dir/artifacts.",
    )

    args = parser.parse_args()
    if args.command == "scan-local":
        result = scan_local_folder(args.path, output_dir=args.output_dir, artifact_store_dir=args.artifact_store_dir)
        print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
