## Public repository for the DEF CON Quals 2020 challenge: `supersafecalc`

### Original challenge

`A really safe calculator. The flag is in /flag`

Released files:

`supersafecalc.pyc`

`stub`

### Running the Challenge
`python -u ./supersafecalc.pyc`

It requires `Python 3.7` and `pyparsing`.

### Source Code
The source code of the challenge is in `prog/`.

To rebuild the challenge run: `./builder.py`

It requires `clang`, `NASM`, and `Python 3.7`.

### Running the Exploit
To run the full exploit: `./run_exploit`

The exploit assumes a flag stored in `/flag`, with the format `OOO{...}`.

The exploit may not be 100% reliable, since it is based on a race condition.

Running:

`cat solution1 | python -u ./supersafecalc.pyc` and
`cat solution2 | python -u ./supersafecalc.pyc`

leak, respectively, the first and the second 8 bytes of the flag.


### Exploit Source Code
The source code of the exploit is in `exploit/`.

To rebuild the exploit run: `./build_exploit.py`.

This command will re-create the `solution1` and `solution2` input files.

 `./build_exploit.py` requires `NASM` and the `keystone-engine` Python package.
 
To install keystone:
1) `sudo apt-get install make cmake build-essential`
2) `pip3 install --no-cache-dir --force-reinstall --no-binary keystone-engine keystone-engine`

