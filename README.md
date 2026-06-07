# rookery

A PGP-first, self-hostable email server that comes with a web mail client and modern standards out-of-the-box.

*In A Song of Ice and Fire, a rookery is a place where the maester keeps the ravens that carry messages between other holdfasts' rookeries.*

## Disclaimer

This project was bootstrapped via vibe coding. I used it to learn alot about the email standard and related technology.
However, I find it too valuable to just be a learning project. Now I'm cleaning it up to get in control again and to proof its secureness.

## Why is it valueable?

If you are a privacy minded person like me, you got only a few options when it comes to email with some ease of use: ProtonMail, Tuta etc.

Rather than becoming a new competitor to those, I want to give the power of the decentralized email standard back into the users hand.

Everyone with a bit of self-hosting/Linux knowledge, can setup their instances for themselves and their friends/family/business.

### The problem: knowledge and spammers

No one holds you back spinning up your own mail server today. But it is rough. To be able to get PGP encryption up and running as well as all other modern email standards you need a lot of knowledge in that domain
and you must be willing to spin up and maintain a stack a few tools for the next years. rookery bundles all of them or better said, what they would do.

But the second problem with self-hosted email stays: spammers. The large email servers (Gmail, Yahoo etc.) won't trust you.

Thats where the concept of smarthosts comes into play. rookery is able to use commercial smarthosts to deliver/receive your mail,
but it can also act as such. So the idea is to grow a network of rookeries that act as smarthosts for new instances then, to overcome that problem.
Over time, your instance' IP will warm up and other mail servers will trust you.

#### But how do I prevent spammers from using my rookery for their stuff?

Everything is invite only. In order to get an account, the operator of the instance needs to create an invitation token/link first.
An operator is able to suspend accounts anytime. The scale of rookery instances is small (friends/family/businesses). They are not huge mail providers like Gmail or Proton.

## So it's using PGP for encryption, right? How can I trust it?

Every use is in control of their private keys, it never touches the server. The flow looks like this:

1. User receives invite link
2. Users signs up (only thing required is an account name)
3. Browser generates key pair, stores private key in localStorage
4. User exports their private key and encrypts it with a passphrase (thats already 2FA!)
5. User logs out, browser storage gets cleared
6. In order to log in again, you need the exported key and the passphrase to decrypt it (no passphrase stored on the server either!)

That has of course one downside: lose your key/passphrase and no one can help you.

## Other features

- Bring your own custom domain! Every rookery instance will give you instructions on how to set them up
- Spam detection via rspamd/Redis (only works for unencrypted emails)
- ClamAV scanning for unencrypted emails
- Very few dependencies to prevent supply chain attacks.
  - While the server/Go uses some, the client/JS only bundles one: OpenPGP.js - https://openpgpjs.org/

## Cool, I'm sold. What do I need?

The idea is to make things very easy for operators, some self-hosting/Linux knowledge will carry you already.

- Buy a domain
- Rent a small VPS, 5€ is enough (or host at home)
- Install git, dig, openssl and Docker on it (tried with Podman, but we need Ports like 25, 80, 443 etc. Easier with Docker)
- Allow incoming traffic on ports:
  - 25
  - 80
  - 443 (tcp/udp)
  - 465 # If you want to act as a smarthost rookery
  - 587 # If you want to act as a smarthost rookery

### My VPS Provider blocks port 25!

Most do. But most of the time it's as easy as requesting unblocking it. In my case (Hetzner) the ticket was even resolved automatically.

### Set it up

And now it becomes very easy, as rookery built in `rookery` CLI carries you:

```sh
sudo mkdir -p /opt/rookery
sudo chown "$USER" /opt/rookery
git clone https://github.com/oleblaesing/rookery.git /opt/rookery
cd /opt/rookery

./rookery init \
    --domain my-rookery.example.com \
    --email mail-for-lets-encrypt@gmail.com \
    --name "My rookery Instance" \

# This will create some config files etc. with generated passwords etc.
# It will also create a systemd unit file with /opt/rookery being hardcoded - be aware!
# The next command will copy the unit file to the systemd directory and reload the units.

sudo ./rookery install
sudo systemctl enable --now rookery

# That's it! rookery is now running. Now check the DNS records you need in order to make it operate properly

./rookery check-dns

# Now you can create an invite link for yourself:

./rookery invite create
```

Upgrading it later:

```sh
cd /opt/rookery
./rookery backup . # Will ask you for a password. You can restore the encrypted back on any instance via ./rookery restore backup.tar.gz.enc
./rookery update
sudo systemctl restart rookery
```

## Local development

```sh
./rookery init \
    --domain localhost \
    --email you@localhost \
    --name "My rookery Dev Box"
./rookery start
./rookery invite create
```
