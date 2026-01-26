# [sendsms](https://github.com/therootcompany/golib/tree/main/net/smsgw/cmd/sendsms)

A little ditty I created for sending mass texts for community and professional events - church, school, meetups, etc.

I bought a $30 Android phone on Facebook marketplace, a $5/month [Tello SIM](https://tello.com/buy/custom_plans), and installed [SMS Gateway for Android™](https://github.com/capcom6/android-sms-gateway) - because Twilio was getting way too expensive with all the plan and compliance fees and such to basically just send a handful of messages now and then.

Prepare a CSV with various message templates like this:

`messages.csv`:

```csv
Name,Phone,Message
Jim,(800) 555-1234,"Hey {Name}, Are you coming to the thing?"
Bob,+18005554321,"Hey {Name}, Are you coming to the thing?"
Joe,1.800.555.3412,"Hey {Name}, Are you coming to the thing?"
```

And send those messages like this:

```sh
sendsms --csv ./messages.csv --start-time '10:00am' --end-time '8:30pm'
```

It let's you know what and when it's going to do:

```text
Warning: skipped 2 rows with missing or invalid data
         (pass --verbose for more detail)

Info: list of 123 messages
Info: start after 10:00am         (8h30m30s ago)
Info: end around 8:30pm           (1h59m30s from now)
Info: delay 20s between messages  (15s + 10s jitter)
Info: This is what a sample message from list look like:

      To: +18015551234 (Joe)
      Hey {Name}, Widget workshop tonight. You coming? - Dude Man
      Hey Joe, Widget workshop tonight. You coming? - Dude Man

Continue? [y/N]
```

And then does it!

```text
# Send to +1 (801) 555-1234
Hey Joe, Widget workshop tonight. You coming? - Dude Man
sleep 21.098s

# Send to +1 (385) 555-4321
Hey Jon, Widget workshop tonight. You coming? - Dude Man
sleep 34.567s
```

With [SMS Gateway for Android™](https://github.com/capcom6/android-sms-gateway), and minimal config:

```sh
SMSGW_BASEURL=http://192.168.1.200:8080
SMSGW_USERNAME=smsgw
SMSGW_PASSWORD=xxxx-xxxx-xxxx-xxxx
```

## Table of Contents

- Usage
- CSV Data
- Templates
- Tips for High Delivery
- Legal

## Usage

```text
Usage of sendsms
  -csv string
    	Path to file with newline-delimited phone numbers (default "./messages.csv")
  -dry-run
    	Skip sending messages and sleeping, runs without confirmation
  -end-time string
    	don't send messages after this time (e.g. 4pm, 23:59) (default "8:30pm")
  -max-duration duration
    	don't send messages for more than this long (e.g. 10m, 2h30m, 6h)
  -min-delay duration
    	don't send messages closer together on average than this (e.g. 10s, 2m) (Default: 20s)
  -print-curl
    	Show full curl commands instead of messages
  -shuffle
    	Randomize the list
  -start-time string
    	don't send messages before this time (e.g. 10:00, 10am, 00:00) (default "10am")
  -verbose
    	Show parse warnings and other debug info
  -y	Confirm without prompting
```

Human, debug, and error output goes to `stderr` (`Info`, `Warn`, `Skip`, `Error`).

Machine-parsable output goes to `stdout` (mostly the comment for tracking success, `curl`, `sleep`)

## Config

1. Copy the example
    ```sh
    cp -RPp ./example.env ./.env
    ```
2. Season `.env` to taste
    ```sh
    SMSGW_BASEURL=http://192.168.1.200:8080
    #SMSGW_BASEURL=https://smsgateway.example.com
    SMSGW_USERNAME=smsgw
    SMSGW_PASSWORD=xxxx-xxxx-xxxx-xxxx
    ```

## CSV Data

The CSV is required to have these 3 named headers:

| Field      | Purpose                                                                         |
| ---------- | ------------------------------------------------------------------------------- |
| `Name`     | Printed with errors, may be used in templates. May be empty.                    |
| `Phone`    | Used for sending messages                                                       |
| `Message`  | A literal or template message that will be templated and sent to this recipient |
| _Whatever_ | All other fields can be used for templates and are otherwise ignored            |

For example:

```csv
Name,Phone,Message,Spice Level,Lucky number
Bob,1800.555-1234,"Hello {Name}, Welcome to the fold!",Hot,2
Suze,8005553456,"Hello {Name}, Welcome to the fold!",,11
Jon,800.555.5678,"Hello {Name}, Be bold! {-Spice Level-}!",Volcano,
,+1 (800) 555-5678,"Hello {Name}, Be bold! {-Spice Level-}!",,37
```

- `Name`, `Phone`, and `Message` are present, as required
- `Spice Level` and `Lucky number` can be used in templates.

## Message Templates

By default, templates do _The Right Thing™_ - meaning that **empty variables cut** the left thing:

`Hey {Name}!` becomes `Hey Joe!` when _Name_ is set and `Hey!` when _Name_ is empty.

The template syntax works like this:

| Syntax     | Example        | "Joe"       | Empty ("") | Comment                       |
| ---------- | -------------- | ----------- | ---------- | ----------------------------- |
| `{Name}`   | `Hey {Name}!`  | `Hey Joe!`  | `Hey!`     | cuts left character if empty  |
| `{Name-}`  | `1,{Name-},3`  | `1,Joe,3`   | `1,3`      | cuts right character if empty |
| `{-Name-}` | `Hey! {Name}!` | `Hey! Joe!` | `Hey!`     | cuts left and right if empty  |
| `{+Name}`  | `Name:{+Name}` | `Name:Joe`  | `Name:`    | keeps left character always   |

You just just as well use `{Spice Level}` or `{Lucky number}` (you just can't use `{Phone}` or `{Message}`).

I DO NOT plan on making a robust template system. I was only interested in solving the _leading space_ / _trailing comma_ problem. \
(but if I did, it would solve that problem too)

## Delivery-Rate Tips

Based on my own experience, having a few different messages (I typically have 4 or 5 for a list of 100+ people) with a delay of at least 10 seconds yields much better delivery than sending the same message as fast as possible.

And be careful to "warm up" the number first before sending long messages or messages with links. To do that, send out messages that get real replies - such as to friends, colleagues, etc.

# Legal

MPL-2.0
