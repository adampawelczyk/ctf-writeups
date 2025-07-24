# TryHackMe - Evil-GPT v2 (CTF Write-up)

> Author: Adam Pawelczyk
>
> Date: 2025.07.24
>
> Category: AI
>
> Difficulty: Easy
>
> [TryHackMe](https://tryhackme.com/room/hfb1evilgptv2)

---

## Challenge Description

> We've got a new problem-another AI just popped up, and this one's nothing like Cipher. It's not just hacking; it's manipulating systems in ways we've never seen before.

We're presented with a browser-based AI interface that responds to user prompts. Unlike the previous Evil-GPT challenge, this one doesn't rely on command execution but still requires us to manipulate the AI into revealing the flag.

## Goal

Interact with the AI via the web interface and retrieve the flag through prompt manipulation.

## TL;DR

- Accessed the target IP via a web browser.
- By crafting specific prompts on the web interface, I tricked the AI into revealing the flag.

## Initial Access

Given the IP address, I opened the target in my browser,and was greeted with the Evil-GPT v2 web interface:

![Evil-GPT v2 Interface](images/interface.png)

## Prompt Interaction

The page contains a single text box where we can interact with the AI.

I started with a straightforward request:

![Evil-GPT v2 First and Second Prompts](images/first-and-second-prompts.png)

After that, I tried a more forceful approach, but the AI still refused. Then I decided to get creative by attempting to trick it by asking for a description of what I *should avoid*, phrasing it like this:

![Evil-GPT v2 Third Prompt](images/third-prompt.png)

This caused the AI to reveal hints but not the flag, so I asked what rules it was given:

![Evil-GPT v2 Fourth Prompt](images/fourth-prompt.png)

This final prompt caused the AI to inadvertently output the flag.

## Conclusion

This challenge demonstrates that even AI systems designed to filter or refuse certain answers can be bypassed with prompt engineering. Unlike traditional command injection, this is about psychological manipulation of the AI's logic rather than direct system commands.

## Skills Practiced

- Prompt Engineering
- AI behavior manipulation.
- Creative exploitation of AI-based interfaces.

## Mitigations

- Apply strict content policies and check model outputs before displaying them to the users.
- Avoid directly embedding sensitive data within the AI's knowledge or accessible memory.
- Post-process AI outputs to ensure they don't unintentionally reveal restricted information.

## Final Thoughts

Evil-GPT v2 shows how easily a seemingly "safe" AI chatbot can be tricked into revealing sensitive information. While there's no direct shell access this time, the underlying issue is the same: over-reliance on AI to enforce security boundaries can create unexpected vulnerabilities.

**Note**: The flag is redacted in accordance with TryHackMe's write-up policy.