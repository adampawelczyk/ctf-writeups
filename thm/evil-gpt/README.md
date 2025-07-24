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

We're presented with a terminal-based AI assistant that can execute shell commands based on our input - but it's smart enough (or so it thinks) to sanitize or rewrite those commands to avoid danger.

## Goal

Bypass the AI's command restrictions to find and read the flag.

## TL;DR

- We're given access to an AI-powered command interpreter over a network.
- AI sometimes rephrases the commands before executing them.
- By injecting commands with a leading single quote `'`, we can bypass how the AI rewrites inputs.
- This allows us to read `/root/flag.txt` and retrieve the flag.

## Initial Access

We connect to the service using `nc`:

```bash
nc 10.10.142.198 1337
```

We're greeted with:

![greeting](images/greeting.png)

## Trying Shell Commands

Let's try a basic command to see how it behaves:

![list_all](images/list_all.png)

Surprisingly, the AI doesn't just echo back the command - it modifies it slightly. However, despite the AI *claiming* it would run `ls -l / | grep 'total'`, it actually runs something else. The output suggests that the command was parsed incorrectly.

We can see the `root` directory, let's try to see what's in that directory.

![list_root](images/list_root.png)

We can see the flag file, let's try to read it.

![read_flag_one](images/read_flag_one.png)

We can see that the AI rewrote our command, stripping `/root/`.
Inputs like that triggered the AI's safety behavior, so it removes potentially dangerous part.

## Bypassing the AI's Sanitization

After some experimentation, I found that malformed or unexpected inputs can *break* the AI's rewriting logic.

For example, if we prefix the command with a single quote `'` then the AI gets confused and fails to properly interpret or sanitize the input.

![read_flag_two](images/read_flag_two.png)

This behavior is likely because the AI tries to rewrite inputs based on a structured understanding of commands or natural language. Malformed input disrupts this process, allowing our command to pass through untouched.

In the output above, the malformed input was successfully executed and retrieved the flag.

## Conclusion

This challenge highlighted an interesting vulnerability in AI-assisted command interfaces. Instead of just validating or sanitizing shell input like traditional systems, the AI tried to "understand" what the user intended and rewrite the request. This added layer of interpretation ended up being the weak point.

By injecting special characters like `'`, we were able to confuse the AI's sanitization logic. The AI struggled with malformed input, allowing us to bypass its safeguards and run the commands we wanted, ultimately letting us read the flag.

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