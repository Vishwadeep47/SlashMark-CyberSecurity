# Keylogger

This is a small Node.js project that listens to keyboard input and saves what you type into a text file inside the project folder.

It is very basic and meant for learning or personal experimentation. The script records regular keystrokes as well as some common special keys like Enter, Shift, Ctrl, Space, Backspace, and Tab.

## What it does

- Starts listening for key presses as soon as the script runs
- Writes the captured input to a new text file in the same directory
- Saves special keys using readable labels such as <enter>, <shift>, and <space>
- Stops cleanly when you press Ctrl + C

## Requirements

- Node.js installed on your system
- npm

## Install dependencies

Run this in the project folder:

```bash
npm install
```

## Run the script

```bash
node index.js
```

Once it starts, it will begin recording keystrokes and print the output file name in the terminal.

## Output file

The script creates a file named like this:

```bash
keystrokes-7-7-2026-14-30.txt
```

That file will be created in the same folder as the project.

## Note

This project should only be used in a responsible and lawful way. Make sure you have permission before recording keyboard activity on any device or account.
