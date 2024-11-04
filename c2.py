import socket
import threading
import re
import shlex
import codecs

# Define the server address and port
address = '127.0.0.1'
port = 8080
buffer_size = 1024

# send message to client
def send_msg(conn, msg):
    conn.send(msg.encode())

# loop to handle individual client in a seperate thread
def handle_client(conn, cid, running):
    exit_flag = False
    conn.settimeout(1.0)
    while not exit_flag and running.is_set():
        try:
            addr = ids[cid]
            exit_flag = handle_msg(conn, cid)
        except socket.timeout:
            pass
        except KeyError:
            # if id changed via nick command
            for i in ids:
                if ids[i] == addr:
                    cid = i 
            continue
        except ConnectionResetError:
            # Handle case where client closes connection unexpectedly
            exit_flag = True
            user_exit(addr)
            print(f"[{cid}] [exit] exception raised")
            break
        except UnicodeDecodeError:
            print(f"[{cid}] [error] unicode characters not currently supported")
    print(f'[server] connection {cid} closed')
    if not exit_flag: send_msg(conn, '[exit]')
    if addr in conns: del conns[addr]
    del ids[cid]
    del rules[addr]
    conn.close()

# handle incoming messages from client
def handle_msg(conn, cid):
    ret = False
    data = conn.recv(buffer_size).decode('utf-8', errors='ignore')
            
    if data:
        if data.startswith('[exit]'):
            ret = True
            user_exit(ids[cid])
            print(f'[{cid}] {data}')
        elif data.startswith('[init] '):
            update_rules(cid, data[7:])
        else:
            handle_update(cid, data)
    return ret

# handles incoming clipboard update notifications 
def handle_update(cid, data):
    if data.startswith('[update] '):
        history[ids[cid]].append(data[9:])
    if not mute:
        line = data.split('\n')
        notif = line[0]
        if len(line) > 1:
            notif =  f"[multi-line] {notif}"
        print(f"[{cid}] {notif}")
    data = data[9:]
    for key in rules[ids[cid]]:
        rule = rules[ids[cid]][key]
        if key.startswith('regex') and rule[2] and re.search(rule[0], data):
            print(f'[{cid}] [rule] applying rule {key}')

            send_msg(conns[ids[cid]], f'[replace] {re.sub(rule[0], rule[1], data)}')
            break

# handles incoming rule updates and changes dictionary to match client
def update_rules(cid, data):
    for rule in data.split("\n"):
        if rule:
            line = shlex.split(rule)
            rules[ids[cid]][line[0]] = [line[1], line[2], line[3] == 'true']
    print(f'[{cid}] [rule] rules reloaded')

# clean user exit
def user_exit(addr):
    del conns[addr]
    del threads[addr]

# clean connection close
def close_connections():
    running.clear()
    for t in threads.values():
        t.join()

# thread to catch new client connections and init client listening thread
def server_listen():
    global curr_id
    while running.is_set():
        try:
            conn, addr = s.accept()

            if not running.is_set():
                break

            cid = str(curr_id)
            print(f'[server] connected to {addr}, id = {cid}')

            ids[cid] = addr
            with id_lock:
                while str(curr_id) in ids:
                    curr_id += 1
            conns[addr] = conn

            history[addr] = []
            rules[addr] = {}
            
            t = threading.Thread(target=handle_client, args=(conn, cid, running))
            threads[addr] = t
            t.start()

        except socket.timeout:
            pass

# checks commands for correct number of args
def arg_err(args, exp_args, usage):
    err = args != exp_args
    if err:
        print(f'[terminal] usage: {usage}')
    return err

# saves logs of clients copy history on server exit
def save_logs():
    log = []
    for client in history:
            hist = history[client]
            hist.reverse()
            curr = 0
            log.append(f"------------ CLIENT {client} ------------")
            while curr < len(hist):
                log.append(f"------------ [item {curr + 1}] ------------")
                log.append(hist[curr])
                curr += 1
            log.append('')

    with codecs.open('cliplog.txt',mode='w+',encoding='utf-8') as f:
        for line in log:
            f.write(f"{line}\n")

######################## COMMANDS ########################

def cmd_exit():
    save_logs()
    close_connections()
    s.close()
    print("[server] exiting")
    exit(0)

def cmd_view(cid, num):
    if cid == 'all':
        for client in ids:
            cmd_view(client, num)
        return
    if num == 'all':
        num = '0'
    num = int(num)

    if cid not in ids:
        print(f"[terminal] [view] id {cid} does not exist")
        return

    hist = history[ids[cid]]
    hist.reverse()

    if num < 0:
        print("[terminal] [view] invalid num")
        return
    if len(hist) == 0:
        print(f"[terminal] [view] no clipboard history for {cid}")
        return
    
    print(f"[terminal] [view] clipboard history for {cid}, most recent first:")
    curr = 0
    while (curr < num or num == 0) and curr < len(hist):
        print(f"------------ [item {curr + 1}] ------------")
        print(hist[curr])
        curr += 1
    print('')

def cmd_help():
    print("""------------ commands: ------------
help: displays list of commands
exit: exits server program
view: view clipboard history of given client ('all' for entire history)
nick: change id of client to given nickname
addr: view address and corresponding id of client
mute/unmute: mutes/unmutes incoming copy notifications

rules: views paste rules for client
reset: resets paste rules to default for client
edit: edits existing paste rule
regex: adds new regex rule to client
""")

def cmd_mute(to_mute):
    global mute
    mute = to_mute
    muted = '' if mute else 'un'
    print(f'[terminal] [mute] incoming notifications {muted}muted')
    print('')

def cmd_addr(cid, all):
    if cid not in ids and cid != 'all':
        print(f"[terminal] [addr] id {cid} does not exist")
        return
    
    if not all: 
        print('client id: address')
        print('---------------------')
    
    if cid == 'all':
        for client in ids:
            cmd_addr(client, True)
        return

    print(f'{cid}: {ids[cid]}')

def cmd_nick(cid, new_cid):
    if cid not in ids:
        print(f"[terminal] [nick] id {cid} does not exist")
        return
    
    if new_cid in ids:
        print(f"[terminal] [nick] new id {new_cid} already exists")
        return

    if '[' in new_cid or ']' in new_cid or new_cid == 'all':
        print(f'[terminal] [nick] new id {new_cid} invalid')
        return
    
    ids[new_cid] = ids[cid]
    del ids[cid]
    print(f'[terminal] [nick] id {cid} renamed to {new_cid}')
    print('')

def cmd_reset(cid):
    if cid == 'all':
        for client in ids:
            cmd_reset(client)
        return
    
    if cid not in ids:
        print(f"[terminal] [addr] id {cid} does not exist")
        return
    rules[ids[cid]] = {}
    send_msg(conns[ids[cid]], '[reset]')

def cmd_rules(cid):
    if cid == 'all':
        for client in ids:
            cmd_rules(client)
        return
    if cid not in ids:
        print(f"[terminal] [rules] id {cid} does not exist")
        return
    
    print(f'[terminal] [rules] rules in client {cid}')
    for rule in rules[ids[cid]]:
        line = rules[ids[cid]][rule]
        print(f"------------ [rule {rule}] ------------")
        print(f'regex: "{line[0]}"')
        print(f'output: "{line[1]}"')
        print(f'enabled: {line[2]}')

def cmd_regex(cid, regex, output):
    if cid == 'all':
        for client in ids:
            cmd_regex(client, regex, output)
        return
    if cid not in ids:
        print(f"[terminal] [regex] id {cid} does not exist")
        return
    
    data = rules[ids[cid]]
    try:
        re.compile(regex)
    except re.error:
        print(f'[terminal] [regex] regex "{regex}" is invalid')
        return
    
    curr = 0
    while f"regex{curr}" in data:
        curr += 1
    data[f"regex{curr}"] = [regex, output, True]
    print(f"[terminal] [regex] [{cid}] new rule regex{curr} created")

def cmd_edit(cid, rid, keyword, value):
    if cid not in ids:
        print(f"[terminal] [edit] id {cid} does not exist")
        return
    
    data = rules[ids[cid]]
    if rid not in data:
        print(f"[terminal] [edit] rule id {rid} does not exist")
        return
    
    # error handling
    if keyword != 'output' and keyword != 'toggle' and keyword != 'regex':
        print(f"[terminal] [edit] invalid keyword {keyword}")
        return
    elif keyword == 'toggle' and value != 'true' and value != 'false':
        print(f"[terminal] [edit] invalid value {value}, must be true or false")
        return

    # check whether to edit rule locally on server or edit on client side
    if not rid.startswith("regex"):
        if keyword == 'regex':
            print(f"[terminal] [edit] cannot change regex of inbuilt rules")
            return
        send_msg(conns[ids[cid]], f'[rule] {rid} {keyword} {value}')
    else:
        rule = data[rid]
        if keyword == 'toggle':
            rule[2] = value == 'true'
        elif keyword == 'regex':
            try:
                re.compile(value)
            except re.error:
                print(f'[terminal] [edit] regex "{value}" is invalid')
                return
        else:
            rule[1] = value
        print(f'[terminal] [edit] regex "{rid}" edited')
    

# Create a socket object
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((address, port))
s.listen()
print("[server] server is listening on", address, ":", port)

# Set a timeout for the socket to make `s.accept()` non-blocking
s.settimeout(1.0)

threads = {}
conns = {}
history = {}
ids = {}
rules = {}
curr_id = 0
id_lock = threading.Lock()
mute = False

running = threading.Event()
running.set()

listen_thread = threading.Thread(target=server_listen, args=())
listen_thread.start()
threads["-1"] = listen_thread

try:
    while True:
        full_cmd = shlex.split(input(''))
        
        if not full_cmd:
            continue

        args = len(full_cmd)
        cmd = full_cmd[0]
        if cmd == 'exit':
            break
        elif cmd == 'view':
            if not arg_err(args, 3, 'view <num to view> <id>'):
                cmd_view(full_cmd[2], int(full_cmd[1]))
        elif cmd == 'mute':
            if not arg_err(args, 1, 'mute'):
                cmd_mute(True)
        elif cmd == 'unmute':
            if not arg_err(args, 1, 'unmute'):
                cmd_mute(False)
        elif cmd == 'help':
            if not arg_err(args, 1, 'help'):
                cmd_help()
        elif cmd == 'addr':
            if not arg_err(args, 2, 'addr <id>'):
                cmd_addr(full_cmd[1], False)
        elif cmd == 'nick':
            if not arg_err(args, 3, 'nick <old id> <new id>'):
                cmd_nick(full_cmd[1], full_cmd[2])
        elif cmd == 'rules':
            if not arg_err(args, 2, 'rules <id>'):
                cmd_rules(full_cmd[1])
        elif cmd == 'reset':
            if not arg_err(args, 2, 'reset <id>'):
                cmd_reset(full_cmd[1])
        elif cmd == 'regex':
            if not arg_err(args, 4, 'regex <id> <regex> <output>'):
                cmd_regex(full_cmd[1], full_cmd[2], full_cmd[3])
        elif cmd == 'edit':
            if not arg_err(args, 5, 'edit <id> <rule id> <regex | output | toggle> <value>'):
                cmd_edit(full_cmd[1], full_cmd[2], full_cmd[3], full_cmd[4])
        else:
            print((f'[terminal] command {cmd} not found'))
        
except KeyboardInterrupt:
    print()
    print("[server] stopped by ctrl+c")
except Exception as e: 
    print(e)
finally:
    cmd_exit()
    

