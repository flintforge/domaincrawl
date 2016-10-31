usage: domaincrawl.py [-h] [--dom [dom]] [--ext [ext]] [--out [out]]
                      [--line [line]] [--resume] [--session [session]]
                      [dic]

Continuous whois query from a dictionnary, log available domains.

positional arguments:
  dic                  dictionnary to load

optional arguments:
  -h, --help           show this help message and exit
  --dom [dom]          only check this domain
  --ext [ext]          TLD to check. Default=.com
  --out [out]          output file results
  --line [line]        starting line of dictionnary
  --resume             resume from last session
  --session [session]  session file
