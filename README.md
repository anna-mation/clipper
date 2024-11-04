# Installation (Windows)

## Server (c2.py)
Run the server first by running the command

```
python c2.py
```
or

```
python3 c2.py
```

## Client (clipboard.cpp)
Then run the following command to compile the client and/or run the `a.exe` file provided

```
g++ clipboard.cpp -lws2_32 -mwindows
```
```
./a.exe
```

To stop `a.exe`, find the process in Task Manager and terminate.

# Server Commands

| Command |  Description  | Syntax |
|:--|:---|:--------- |
| help   | Displays list of commands | `help` |
| exit   | Exits  | `exit` |
| view   | View clipboard history of given client (set id as ‘all’ for all clients, and num as ‘all’ for all history) | `view <num to view> <id>` |
| nick   | Change id of client to given nickname | `nick <old id> <new id>` |
| addr   | View address and corresponding id of client (set id as ‘all’ for all clients)  | `addr <id>` |
| mute/unmute   | Mutes/unmutes incoming copy notifications | `<mute \| unmute>` |
| rules   | Views paste rules for client (set id as ‘all’ for all clients) | `rules <id>` |
| reset    | Resets paste rules to default for client (set id as ‘all’ for all clients) | `reset <id>` |
| edit   | Edits existing paste rule | `edit <id> <rule id> <regex \| output \| toggle> <value>` |
| regex   | Adds new regex rule to client (set id as ‘all’ for all clients) | `regex <id> <regex> <output>` |

# Logs
The client logs are located in `cliplog.txt` in the same directory as `c2.py`, created after the server terminates.
