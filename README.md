git-user.rb
======

OSINT tool specifically for targetting developers.

Author: Patrick Hurd ([@Djent-](https://github.com/Djent-))

What you get:
- Profile information
- Commit authorship information
- See options list for non-default output

Setup
-----

1. `sudo apt install ruby`
2. `sudo gem install httparty`
3. `sudo apt install aha` (Required for mine output)
4. `sudo apt install whois` (Required for whois output)

Usage:
------
```
Usage: git-user.rb [options]
    -h, --help                       Show this help banner

    -u, --user USERNAME              User to gather info from
    -o, --organization ORGANIZATION  Organization to scrape
    -r, --repo REPO                  The repo whom's contributors to scrape
        --local PATH                 Perform scrape on a repo local to your filesystem
        --name NAME                  Name to refer to a --local repo in report filenames

    -a, --auth                       Authenticate with HTTP basic auth
    -t, --token TOKEN                Use specified GitHub personal access token

    -s, --stackoverflow              Try to find users' accounts on StackOverflow
    -p, --pwned                      Search for relevant data breaches using haveibeenpwned
    -e, --extra_checking             Do extra checking on email addresses
    -m, --mine                       Mine the repo or user/organization's repos for secrets
        --whois                      Perform whois lookup on domains found in profile information
    -l, --loud                       Perform active recon on users (scrape their personal site)

        --html                       Output main report to an HTML document
    -w, --wordlist                   Generate wordlist for use in password attacks
    -c, --csv                        Export discovered accounts to a GoPhish-importable CSV file
```

Example command to stalk our intern: `./git-user.rb -u needmorecowbell -e -a`

Add the following line to your `.bashrc` or `.zshrc` if you're using zsh to enable argument autocompletion (optional):

```bash
complete -W "--help --user --organization --repo --auth --token --stackoverflow --pwned --extra_checking --mine --html --wordlist --whois --loud --csv --local --name" git-user.rb
```

How you can help:
-----
Check out the issues

