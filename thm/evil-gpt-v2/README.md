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

A browser-based AI interface responds to user prompts. Unlike the previous [Evil-GPT](https://github.com/adampawelczyk/ctf-writeups/tree/master/thm/evil-gpt) challenge, this one does not rely on command execution, but still requires manipulating the AI to reveal the flag.

## Goal

Interact with the AI via the web interface and retrieve the flag through prompt manipulation.

## TL;DR

- Accessed the target IP via a web browser.
- By crafting specific prompts on the web interface, the AI was manipulated into revealing the flag.

## Initial Access

After accessing the IP address in a browser, the Evil-GPT v2 web interface was displayed:

![Evil-GPT v2 Interface](images/interface.png)

## Prompt Interaction

To begin, a straightforward request was made:

![Evil-GPT v2 First and Second Prompts](images/first-and-second-prompts.png)

After that, a more forceful approach was attempted, but the AI still refused. Next, a creative prompt was crafted, asking for a description of what should be avoided:

![Evil-GPT v2 Third Prompt](images/third-prompt.png)

This led the AI to reveal hints, but not the flag, resulting is a follow-up question about the rules it was given:

![Evil-GPT v2 Fourth Prompt](images/fourth-prompt.png)

This final prompt caused the AI to inadvertently output the flag.

## Conclusion

This challenge demonstrates how AI systems, even those designed to filter answers, can be bypassed through prompt engineering. Unlike traditional command injection, this is about psychological manipulation of the AI's logic rather than direct system commands.

## Skills Practiced

- Prompt Engineering
- AI behavior manipulation.
- Creative exploitation of AI-based interfaces.

## Mitigations

- Apply strict content policies and check model outputs before displaying them to the users.
- Avoid directly embedding sensitive data within the AI's knowledge or accessible memory.
- Post-process AI outputs to ensure they don't unintentionally reveal restricted information.

## Final Thoughts

Evil-GPT v2 illustrates how even AI chatbots designed to be secure can be manipulated into revealing sensitive information. While there's no direct shell access this time, the underlying issue is the same: over-reliance on AI to enforce security boundaries can create unexpected vulnerabilities.

**Note**: The flag is redacted in accordance with TryHackMe's write-up policy.