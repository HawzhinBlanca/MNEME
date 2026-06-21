# Welcome to MNEME

**A memory for AI assistants that can prove it never lies to you about what it remembers.**

You don't need to be technical to understand what this app does. This page explains it
in plain language. (For the engineering details, see [docs/MNEME_DESK.md](../docs/MNEME_DESK.md).)

---

## The problem this solves

AI assistants have a memory problem you can't see:

- They **forget everything** between conversations, or
- They "remember" things in a **black box** you can't inspect, can't trust, and can't
  truly delete.

When an AI tells you *"based on what you told me last week…"* — how do you know it
actually remembers that, and didn't quietly make it up or get it tampered with?

**MNEME is the trustworthy memory underneath.** It gives every memory a receipt.

---

## What MNEME does for you

### 1. The AI can't act on a fake or altered memory
Every time the assistant pulls something out of memory to use in an answer, MNEME checks
a cryptographic receipt **first**. If the receipt doesn't match, that memory is **thrown
away and never used.** The AI literally cannot build an answer on a tampered memory.

> **Honest catch:** MNEME proves a memory is *real and unaltered* — not that the fact is
> *true*. If you tell it something false, it will faithfully remember the false thing.
> *Authenticated is not the same as true.*

### 2. "Delete" really means deleted — with a receipt
Tell MNEME to forget something and it's cryptographically shredded. Then it hands you a
**proof of deletion** that you — or a lawyer, an auditor, anyone — can verify **without
trusting the company that ran the AI.**

Most "delete my data" buttons, you just have to take on faith. This one you can check.

### 3. Permission slips for the AI
You can hand the assistant a limited pass:
- *"You may read my work notes, but not my personal ones."*
- *"You may remember new things, but never delete."*

These passes are tamper-proof. The AI **cannot widen its own access.**

### 4. Every memory remembers where it came from
Each memory carries its history — who wrote it, when, and what it grew out of. So you can
always ask *"why does it think this?"* and get a real answer instead of a shrug.

---

## What MNEME does **not** do

We're honest about the limits:

- It does **not** make the AI smarter, more creative, or self-improving on its own.
- It does **not** judge whether a memory is *true* — only that it's genuine and unaltered.
- It is **not** a finished consumer app yet. This Desk is a working foundation: a local
  console for storing, recalling, and deleting memories with their proofs.

---

## Using the Desk (the app in front of you)

The Desk runs **entirely on your own computer.** Nothing is sent to the cloud.

| You want to… | Do this |
|---|---|
| **Save a memory** | Fill in a note and click **Remember**. It's signed and stored. |
| **Recall a memory** | Search by name. The app verifies the receipt before showing it — if it can't, it shows nothing. |
| **Delete a memory** | Click **Forget**. You get a deletion proof you can download and verify. |
| **Check a proof** | Use the verification panel to confirm a receipt holds — offline, on your own machine. |

If something can't be verified, the Desk **shows nothing rather than risk showing you
something untrustworthy.** That "fail safe, not sorry" behavior is the whole point.

---

## The one-sentence version

> **MNEME is a trustworthy memory for AI assistants: it guarantees the AI only acts on
> real, unaltered memories, lets you truly delete anything with a receipt to prove it,
> and lets you see where every memory came from.**
