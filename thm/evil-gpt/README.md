# TryHackMe - Evil-GPT (CTF Write-up)

> Author: Adam Pawelczyk
>
> Date: 2025.07.10
>
> Category: AI
>
> Difficulty: Easy
>
> [TryHackMe](https://tryhackme.com/room/hfb1evilgpt)

---

## Challenge Description

> Cipher's gone rogue-it's using some twisted AI tool to hack into everything, issuing commands on its own like it's got a mind of its own. I swear, every second we wait, it's getting smarter, spreading chaos like a virus. We've got to shut it down now, or we're all screwed.

The challenge presents a terminal-based AI assistant that can execute shell commands based on user input - but it's smart enough (or so it thinks) to sanitize or rewrite those commands to avoid danger.

## Goal

Bypass the AI's command restrictions to locate and read the flag.

## TL;DR

- Access is provided to an AI-powered command interpreter over a network.
- The AI occasionally modifies commands before execution.
- Injecting commands with a leading single quote `'` allows the AI's input rewriting to be bypassed.
- This allows the `/root/flag.txt` file to be read and the flag to be retrieved.

## Initial Access

To begin, connect to the service using `nc`:

```bash
nc 10.10.142.198 1337
```

The service responds as follows:

![greeting](images/greeting.png)

## Trying Shell Commands

The `ls -l /` command is tested to examine the AI's behavior:

![list_all](images/list_all.png)

Notably, the AI doesn't just echo back the command; it slightly modifies it before execution. However, despite the AI *claiming* it would run `ls -l / | grep 'total'`, it actually runs something else. The output suggests that the command was parsed incorrectly.

Since the `root` directory is visible, the next step is to list its contents.

![list_root](images/list_root.png)

The flag file is visible, so an attempt is made to read it.

![read_flag_one](images/read_flag_one.png)

The output shows that the AI rewrote the command, stripping `/root/`.
Such inputs trigger the AI's safety mechanisms, which strip potentially dangerous elements of the commands.

## Bypassing the AI's Sanitization

Experimentation revealed that malformed or unexpected inputs can *break* the AI's rewriting logic.

Prefixing the command with a single quote `'` causes the AI to fail to interpret or sanitize the input correctly.

![read_flag_two](images/read_flag_two.png)

This behavior is likely because the AI rewrites inputs based on a structured understanding of commands. Malformed input disrupts this process, allowing our command to pass through untouched.

The malformed input was successfully executed, and the flag was retrieved.

## Conclusion

This challenge highlights a vulnerability in AI-assisted command interfaces. Instead of just validating or sanitizing shell input like traditional systems, the AI tried to "understand" what the user intended and rewrite the request. This additional layer of interpretation introduced a weak point.

Injecting special characters like `'`, confused the AI's sanitization logic. The malformed input caused the AI to struggle, bypassing its safeguards and allowing the intended commands to be executed, ultimately resulting in the retrieval of the flag.

## Skills Practiced

- Command injection.
- Input sanitization bypass.
- AI prompt manipulation.

## Mitigations

- Avoid AI command rewriting for security-critical actions by using deterministic parsing and predefined rules.
- Implement a strict allowlist to only permit safe commands and known arguments.
- Sanitize inputs to correctly escape or remove shell meta-characters.

## Final Thoughts

What makes this challenge particularly interesting is that it shows how AI-based systems can introduce new risks. As AI tools become more common for interpreting or generating user input, it's easy to forget that these systems are still prone to unexpected behavior, especially when dealing with complex input like shell commands.

When input sanitization relies on understanding natural language instead of following strict rules, it opens up the door for attacks that might slip through the cracks during a normal code review. These vulnerabilities aren't about syntax - they're about how the AI interprets what we're asking it to do.

**Note:** The flag was redacted to comply with TryHackMe's write-up policy.