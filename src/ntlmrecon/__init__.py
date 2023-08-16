import click
import json
import csv
import os

from termcolor import colored
from colorama import init as init_colorama
from multiprocessing.dummy import Pool as ThreadPool
from ntlmrecon.ntlmutil import gather_ntlm_info
from ntlmrecon.misc import print_banner, INTERNAL_WORDLIST
from ntlmrecon.inpututils import readfile_and_gen_input, read_input_and_gen_list

init_colorama()
CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help", "help"])


def write_csv_record(file, records):
    writer = csv.writer(file)
    writer.writerow([
        "URL", "AD Domain Name", "Server Name", "DNS Domain Name", "FQDN", "Parent DNS Domain"
    ])
    for record in records:
        csv_record = [list(record.keys())[0]] + list(record[list(record.keys())[0]]["data"].values())
        writer.writerow(csv_record)


def write_json_record(file, records):
    for record in records:
        r = {
            "url": list(record.keys())[0],
            "domain": list(record.values())[0]["data"]["AD domain name"],
            "server": list(record.values())[0]["data"]["Server name"],
            "dns_domain": list(record.values())[0]["data"]["DNS domain name"],
            "fqdn": list(record.values())[0]["data"]["FQDN"],
            "parent": list(record.values())[0]["data"]["Parent DNS domain"],
        }
        file.write(json.dumps(r) + "\n")


def write_records(records, filename, output_type):
    mode = "a" if os.path.exists(filename) else "w+"
    with open(filename, mode) as file:
        if output_type == "csv":
            if mode == "w+":
                write_csv_record(file, records)
        elif output_type == "json":
            write_json_record(file, records)


def print_records(results):
    for record in results:
        r = {
            "url": list(record.keys())[0],
            "domain": list(record.values())[0]["data"]["AD domain name"],
            "server": list(record.values())[0]["data"]["Server name"],
            "dns_domain": list(record.values())[0]["data"]["DNS domain name"],
            "fqdn": list(record.values())[0]["data"]["FQDN"],
            "parent": list(record.values())[0]["data"]["Parent DNS domain"],
        }
        print(json.dumps(r))


@click.command(context_settings=CONTEXT_SETTINGS)
@click.option("--input", "-i", help="Pass input as an IP address, URL or CIDR to enumerate NTLM endpoints")
@click.option("--infile", "-I", help="Pass input from a local file", type=click.Path(exists=True, resolve_path=True, dir_okay=False))
@click.option("--wordlist", help="Override the internal wordlist with a custom wordlist", type=click.Path(exists=True, resolve_path=True, dir_okay=False))
@click.option("--threads", help="Set number of threads (Default: 10)", default=10, show_default=True, type=int)
@click.option("--output-type", "-o", help="Output type", default="json", show_default=True, type=click.Choice(["csv", "json", "stdout"]))
@click.option("--outfile", "-O", help="Set output file name", default=None, show_default=True, type=click.Path(resolve_path=True, dir_okay=False))
@click.option("--random-user-agent", is_flag=True, help="Randomize user agents when sending requests (Default: False)")
@click.option("--force-all", is_flag=True, help="Force enumerate all endpoints even if a valid endpoint is found for a URL (Default: False)")
@click.option("--shuffle", is_flag=True, help="Break order of the input files")
@click.option("-f", "--force", is_flag=True, help="Force replace output file if it already exists")
@click.option("-p", "--proxy", help="Use a proxy to connect to the target", default=None)
@click.option("--silent", "-s", is_flag=True, help="Suppress all output except errors.")
def main(
    input,
    infile,
    wordlist,
    threads,
    output_type,
    outfile,
    random_user_agent,
    force_all,
    shuffle,
    force,
    silent,
    proxy,
):
    if not input and not infile:
        click.echo(colored("[!] Please specify either an input or an input file. Use --help for more information", "red"))
        return

    outfile = outfile or (f"ntlmrecon.{output_type}" if output_type != "stdout" else None)

    if outfile and os.path.exists(outfile) and not force and output_type != "stdout":
        os.remove(outfile)

    records = read_input_and_gen_list(input, shuffle=shuffle) if input else readfile_and_gen_input(infile, shuffle=shuffle)
    wordlist = INTERNAL_WORDLIST if not wordlist else open(wordlist).read().splitlines()

    pool = ThreadPool(threads)
    for record in records:
        if not silent:
            print(colored(f"[+] Brute-forcing {len(wordlist)} endpoints on {record}", "yellow"))

        all_combos = [f"{record}/{word.lstrip('/')}" for word in wordlist]

        def gather(combo):
            return gather_ntlm_info(combo, random_user_agent, silent, proxy)

        results = [result for result in pool.map(gather, all_combos) if result]

        if results:
            if output_type == "stdout":
                print_records(results)
            else:
                write_records(results, outfile, output_type)
                if not silent and output_type != "stdout":
                    print(colored(f"[+] Output saved to {outfile} ", "green"))


if __name__ == "__main__":
    print_banner()
    main()
