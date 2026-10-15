import QtQuick
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui

// omdrop -- receive files from nearby Apple devices.
//
// This panel owns no settings. `bin/omdrop` is the single source of truth: it
// asks systemd whether the receiver is up and asks the radio side whether
// anyone can actually see us, and answers in one JSON line. We poll it while
// the panel is open and while the bar icon is lit, so the widget stays right
// when a window expires or something else turns receiving off.
//
// The three answers that matter are deliberately distinguishable:
//   receiving + visible      someone's sheet can show us
//   receiving + not visible  the server is up but nothing is advertising
//   visible == null          the radio half is absent; we genuinely cannot
//                            tell, and must not draw that as either answer
Panel {
  id: root
  moduleName: "netmojo.omdrop"
  ipcTarget: "netmojo.omdrop"
  manageIpc: false

  // The bar sizes each slot from its item's implicitWidth. Ui/Panel does not
  // provide one, so without this the slot is zero-wide: the widget loads, runs
  // and reports healthy, and paints nothing. Every built-in bar widget sets it.
  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  // One of the Everyone / Contacts Only tabs. The chosen one is lit; the
  // other stays dark until hovered, when it brightens to say it can be clicked.
  component AudienceTab: Item {
    id: tab
    property string glyph
    property string label
    property bool selected
    signal chosen()

    implicitWidth: tabRow.implicitWidth
    implicitHeight: tabRow.implicitHeight

    readonly property bool hovered: tabMouse.containsMouse && !selected
    readonly property color tint: selected ? root.foreground
                                  : hovered ? Qt.darker(root.foreground, 1.4)
                                  : Qt.darker(root.foreground, 2.0)

    Row {
      id: tabRow
      spacing: Style.space(6)
      Text {
        text: tab.glyph
        color: tab.tint
        font.family: root.fontFamily
        font.pixelSize: Style.font.bodySmall
        anchors.verticalCenter: parent.verticalCenter
      }
      Text {
        text: tab.label
        color: tab.tint
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        font.bold: true
        font.letterSpacing: 1.2
        anchors.verticalCenter: parent.verticalCenter
      }
    }

    MouseArea {
      id: tabMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: tab.selected ? Qt.ArrowCursor : Qt.PointingHandCursor
      onClicked: tab.chosen()
    }
  }

  // Shipped beside this file so the widget works without anything on PATH.
  readonly property string cli: Qt.resolvedUrl("bin/omdrop").toString().replace("file://", "")

  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color urgent: bar ? bar.urgent : Commons.Color.urgent
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  property bool installed: false      // the CLI answered at all
  property bool receiving: false
  property int visibility: -1         // -1 unknown, 0 no, 1 yes
  property int remaining: -1
  property string deviceName: ""
  property string downloadDir: ""
  property string blockedReason: ""
  // Who may send: "everyone" or "contacts" (the saved `omdrop visibility`),
  // and how many people the Contacts Only allow-list holds.
  property string audience: "everyone"
  property int senders: 0

  property string lastError: ""

  readonly property string homePath: Quickshell.env("HOME") || ""

  // ~/Downloads reads better than /home/someone/Downloads.
  function tildify(p) {
    if (homePath !== "" && p.indexOf(homePath) === 0) return "~" + p.substring(homePath.length)
    return p
  }

  // What the radio side says is wrong, in words rather than a token.
  readonly property string reasonText: {
    switch (blockedReason) {
    case "no_awdl0":   return "The AWDL interface is missing. The Wi-Fi driver needs loading."
    // The retry advice this used to carry was disproved by five identical
    // failures: parked-with-a-template-loaded cannot be cleared from userspace,
    // so a retry cannot succeed. The CLI's own message names the way out, and
    // lastError shows it verbatim rather than paraphrasing it into advice.
    case "parked":     return ""
    case "ok":
    case "expired":
    case "stopped":
    case "":           return ""
    // Anything unrecognised is worth showing rather than swallowing, but only
    // when something is actually wrong: while we are visible there is no
    // problem to report, whatever token the radio side is using for "fine".
    default:           return visibility === 1 ? "" : "The radio side reports: " + blockedReason
    }
  }
  property bool busy: false
  // Which way the press was going, captured when it was pressed. Deriving it
  // from `receiving` reads the state we are moving away from, and `omdrop on`
  // starts the receiver before the radio -- so a poll lands mid-flight, sees
  // receiving=true, and the headline of a turn-ON says "Turning off".
  property bool turningOn: false
  property int busyElapsed: 0
  // The radio gate takes about 10 s, and `omdrop on` returns before the radio
  // has settled, so silence here is indistinguishable from a hang. Count up
  // once it is long enough to be worth saying.
  property string busyDots: "."

  Timer {
    interval: 450
    repeat: true
    running: root.busy || root.settling
    onTriggered: root.busyDots = root.busyDots.length >= 3 ? "." : root.busyDots + "."
    onRunningChanged: if (!running) root.busyDots = "."
  }

  // The radar's status line counts through ".", "..", "..." and then none,
  // so the pause reads as a breath rather than a stall.
  property string radarDots: "."
  Timer {
    interval: 450
    repeat: true
    running: root.radarWorking
    onTriggered: root.radarDots = root.radarDots === "..." ? "" : root.radarDots + "."
    onRunningChanged: if (!running) root.radarDots = "."
  }

  Timer {
    interval: 1000
    repeat: true
    running: root.busy
    onTriggered: root.busyElapsed++
    onRunningChanged: if (!running) root.busyElapsed = 0
  }

  // The CLI answering is not the same as this machine being able to receive.
  // `visible: null` means the radio half is missing, which is the state the
  // struck-through icon and the "Not available" copy are for.
  readonly property bool usable: installed && visibility !== -1

  // The receiver comes up in a moment and the radio gate takes about 10 s
  // after that, so there is a short stretch where the window is genuinely
  // open and nobody can see us yet -- which is normal, and must not be
  // reported in the same words as a radio that failed.
  // Counted, not computed from a clock: a binding on Date.now() never
  // re-evaluates, so it would latch at whatever it read first.
  property int settleElapsed: 0
  readonly property bool settling: receiving && visibility !== 1 && settleElapsed < 200

  Timer {
    interval: 1000
    repeat: true
    running: root.receiving && root.visibility !== 1
    onTriggered: root.settleElapsed++
    onRunningChanged: if (!running) root.settleElapsed = 0
  }

  // Discrete stops rather than a free 0-120 scale: the useful values are few,
  // and the two ends are modes, not durations. `settings.windowMinutes` (the
  // widget's own config) seeds the starting position; moving the slider
  // overrides it for this session.
  readonly property var windowStops: [
    { arg: "once",    label: "One file, then off" },
    { arg: "1m",      label: "1 minute" },
    { arg: "5m",      label: "5 minutes" },
    { arg: "10m",     label: "10 minutes" },
    { arg: "15m",     label: "15 minutes" },
    { arg: "30m",     label: "30 minutes" },
    { arg: "60m",     label: "1 hour" },
    { arg: "forever", label: "Until I turn it off" }
  ]
  property int windowIndex: defaultWindowIndex()
  readonly property string windowArg: windowStops[windowIndex].arg

  function defaultWindowIndex() {
    var want = settings.windowMinutes || 10
    for (var i = 0; i < windowStops.length; i++)
      if (windowStops[i].arg === want + "m") return i
    return 3
  }

  // The slider is a control AND a report: while a window is running it has to
  // show the window that is running, not the setting the widget was configured
  // with. Turning on with "Until I turn it off" and reopening the panel showed
  // 10 minutes -- the toggle told the truth and the row beneath it did not.
  //
  // Only on a change of mode, so a running window never fights a user who is
  // dragging the slider to pick the next one. Going off leaves the last
  // position alone: it is what they chose, and most likely what they want next.
  //
  // A mode the user just asked for is not news: rescheduleWindow() records it
  // here so the poll that follows a reschedule does not read its own result as
  // a change and move the slider under the hand that just set it.
  property string windowMode: ""
  function syncWindowToRunning(mode) {
    // A hand on the slider outranks anything a poll has to say.
    if (windowPicking) return
    if (mode === windowMode) return
    windowMode = mode
    var i
    if (mode === "once")    { windowIndex = 0; return }
    if (mode === "forever") { windowIndex = windowStops.length - 1; return }
    if (mode === "timed" && remaining > 0) {
      // Only what is LEFT is knowable, so land on the shortest stop that could
      // still be running: a 10-minute window with 4 minutes left reads as 5.
      var mins = remaining / 60
      for (i = 1; i < windowStops.length - 1; i++)
        if (parseInt(windowStops[i].arg) >= mins) { windowIndex = i; return }
    }
  }
  readonly property color barIconColor: receiving ? barForeground : Qt.darker(barForeground, 1.55)


  // The headline names the state of the thing the switch controls: Omdrop is
  // on or it is off. "Not receiving" described a symptom, and read as a
  // complaint about a machine that was working exactly as asked.
  //
  // The shades of "on" -- advertising but unanswered, receiver up with nothing
  // on the radio -- live in detailText, which is where an explanation belongs.
  // The one exception stays a headline: a window that is open while nothing
  // can see us is a fault, not a nuance, and must not read as "on".
  readonly property string stateText: {
    if (!usable) return "Not available"
    if (busy) return (turningOn ? "Turning on" : "Turning off") + busyDots
    if (settling) return "Waking the radio" + busyDots
    if (!receiving) return "Omdrop off"
    if (visibility === 0) return "Nobody can see you yet"
    return "Omdrop on"
  }


  // One sentence, naming what they will see and roughly when. In Contacts Only
  // it names who, because "nearby Apple devices" would overstate it.
  readonly property string visibleText: {
    var who = deviceName !== "" ? "\"" + deviceName + "\"" : "this computer"
    if (audience === "contacts") {
      if (senders === 0) return "Your known-senders list is empty, so everyone is refused. "
                              + "Add people with: omdrop senders add EMAIL"
      return "Only your " + senders + (senders === 1 ? " known sender" : " known senders")
             + " should see " + who + " in AirDrop, after 10 seconds."
    }
    return "Nearby Apple devices should see " + who + " in AirDrop, after 10 seconds."
  }
  // An empty allow-list is a window nobody can use, so it reads as a fault.
  readonly property bool detailUrgent: detailText === visibleText && audience === "contacts" && senders === 0

  readonly property string detailText: {
    if (!usable) return doctorText !== "" ? doctorText
                                          : "Needs the AWDL radio support this plugin's README describes."
    if (settling) return "The radio takes a few seconds to come up."
    if (lastError !== "") return lastError
    if (reasonText !== "") return reasonText
    if (!receiving && doctorText !== "") return doctorText
    if (!receiving) return "Nearby Apple devices cannot see this computer."
    if (visibility === 0) return "The receiver is up, but nothing is advertising on the radio."
    if (visibility === -1) return "Cannot tell whether anyone can see us."
    return visibleText
  }

  // The row that set the window becomes the row that reports it: while a timed
  // window runs, the chosen duration is replaced by what is left of it. Only
  // for timed windows -- "one file" and "until I turn it off" have nothing to
  // count down, so they keep their label.
  //
  // While a hand is on the slider the label comes back, whatever is running:
  // a countdown answers a question nobody is asking mid-drag, and without the
  // label there is no way to see which stop you have landed on.
  property bool windowPicking: false
  readonly property bool countingDown: receiving && remaining > 0 && !windowPicking
  readonly property string windowValueText: {
    if (!countingDown) return windowStops[windowIndex].label
    var m = Math.floor(remaining / 60), sec = remaining % 60
    return (m < 10 ? "0" : "") + m + ":" + (sec < 10 ? "0" : "") + sec
  }

  readonly property string countdownText: {
    if (busy) {
      if (busyElapsed < 4) return ""
      var m = Math.floor(busyElapsed / 60), s2 = busyElapsed % 60
      var phase = turningOn ? "WAKING THE RADIO" : "STOPPING"
      return phase + " · " + m + ":" + (s2 < 10 ? "0" : "") + s2
    }
    return ""
  }

  function toggleOmdrop() {
    if (busy || !usable) return
    turningOn = !receiving
    busy = true
    lastError = ""
    toggleProc.running = true
  }

  // Moving the slider during a live window resets that window to the new
  // selection, counting from now: choosing 10 minutes leaves ten minutes,
  // whatever was left before. Without this the row only described the NEXT
  // press, so a user extending a window that was about to close had no way to
  // do it but turn Omdrop off and on again.
  //
  // On release rather than on every drag position: each call re-arms the
  // window timer and rewrites the radio's deadline, and a drag across the
  // slider would otherwise fire one of those per stop it passes over.
  function rescheduleWindow() {
    if (!receiving || busy || !usable) return
    windowMode = windowArg === "once" || windowArg === "forever" ? windowArg : "timed"
    lastError = ""
    rescheduleProc.command = [root.cli, "on", root.windowArg]
    rescheduleProc.running = true
  }

  // Deliberately not `busy`: the switch is not moving and the radio is already
  // up, so this is a quiet adjustment rather than a transition to narrate. A
  // refusal still has to surface, and the poll afterwards is what redraws the
  // countdown against the new deadline.
  Process {
    id: rescheduleProc
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.lastError = text.trim()
    }
    onExited: function(code) {
      if (code === 0) root.lastError = ""
      root.refreshStatus()
    }
  }

  Process {
    id: toggleProc
    command: [root.cli, "toggle", root.windowArg]
    // A refusal is the interesting case: the CLI declines rather than
    // pretending, and without this the panel would just sit there.
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.lastError = text.trim()
    }
    onExited: function(code) {
      root.busy = false
      if (code === 0) root.lastError = ""
      root.refreshStatus()
    }
  }

  // The name is validated by the CLI and the receiver, not here: the CLI
  // refuses a bad value and puts the old one back if the receiver will not
  // start with the new one. Either way its message is shown, and the field
  // returns to the name in effect on the next poll.
  //
  // An edit is kept when the field loses focus, not only on Enter: closing
  // the panel or clicking elsewhere after typing a name is the ordinary way to
  // finish, and discarding the name then looked like a rename that failed.
  // pendingName is the name on its way to the CLI; one asked for while an
  // earlier one is still being applied goes next.
  property string pendingName: ""
  property string sentName: ""
  Process {
    id: setNameProc
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: if (text.trim() !== "") root.lastError = text.trim()
    }
    onExited: function(code) {
      if (code === 0) root.lastError = ""
      if (root.pendingName !== root.sentName) {
        root.startSetName()
        return
      }
      root.pendingName = ""
      root.refreshStatus()
    }
  }

  function startSetName() {
    sentName = pendingName
    setNameProc.command = [root.cli, "name", sentName]
    setNameProc.running = true
  }

  function setDeviceName(v) {
    if (v.trim() === "" || v === shownName) return
    pendingName = v
    if (!setNameProc.running) startSetName()
  }

  // What the field shows when nobody is typing in it.
  readonly property string shownName: pendingName !== "" ? pendingName : deviceName

  // The download folder is chosen in Nautilus, not typed: a path typed into a
  // field is a path somebody has to get exactly right, and the chooser can
  // only answer with one that exists. The CLI owns the whole exchange --
  // opening the chooser where the folder is now, and applying the answer --
  // so a cancel is just an exit with nothing to say.
  property bool pickingDir: false
  Process {
    id: pickDirProc
    command: [root.cli, "dir", "--pick"]
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: if (text.trim() !== "") root.lastError = text.trim()
    }
    onExited: { root.pickingDir = false; root.open(); root.refreshStatus() }
  }

  function pickDownloadDir() {
    if (pickingDir) return
    pickingDir = true
    lastError = ""
    pickDirProc.running = true
    // The panel is a layer above every window, so a chooser cannot come up
    // over it: it steps aside while the chooser is open and comes back with
    // the answer.
    root.close()
  }

  // ---------------------------------------------------------------- radar
  //
  // Two listings run while the radar is open. The bare one is passive and
  // quick, so it is polled for the dots and their signal. The named one
  // connects to every peer and takes half a minute, so it runs back to back:
  // each lookup starts when the last one ends, and the names it finds are
  // kept for the rest of the session, since a device answers only while its
  // AirDrop is listening and would otherwise lose its label between lookups.
  property bool radarOpen: false
  property bool soundOn: true
  property var peers: []            // [{mac, rssi, name}] -- the last listing, names merged in
  property var peerNames: ({})      // mac -> name, everything learnt this session
  property bool namesResolved: false  // a name lookup has answered at least once
  property var flashedMacs: ({})    // rows that have had their arrival flash
  readonly property bool scanning: radarOpen && root.opened && receiving && visibility === 1
  // The line under the heading. Empty once there is a list to look at.
  readonly property string radarStatus: {
    if (!receiving) return "Turning Omdrop on"
    if (!scanning) return "Waiting for the radio"
    if (peers.length === 0) return "Searching for peers"
    if (!namesResolved) return "Resolving peer names"
    return ""
  }
  readonly property bool radarWorking: radarOpen && radarStatus !== ""
  // The device a send is going to stays listed until that send is over, even
  // if a poll stops hearing it mid-transfer, and even if it never gave a name:
  // its row is where the progress is. The address is the send's identity; a
  // name that arrives meanwhile only relabels the row.
  readonly property var namedPeers: {
    var list = peers.filter(function(p) { return p.name !== "" })
    if (sendingTo !== "" && !list.some(function(p) { return p.mac === sendingTo }))
      list.push({ mac: sendingTo, rssi: null, name: peerNames[sendingTo] || sendingName })
    return list
  }

  // The rows under the heading, kept in place across polls. `peers` is a new
  // array on every listing (every 2 s) and every name lookup, and a Repeater
  // over an array rebuilds all its rows on each one: a click whose press and
  // release straddled a rebuild went to a row that no longer existed, so it
  // did nothing but take the tooltip with it. Keyed by address, as the radar's
  // dots are, a row is only created when its device arrives and only removed
  // when it leaves; a name that changes relabels it, and rows keep the order
  // they arrived in rather than shuffling under the pointer.
  ListModel { id: peerRows }
  onNamedPeersChanged: {
    var want = {}
    for (var i = 0; i < namedPeers.length; i++)
      want[namedPeers[i].mac] = namedPeers[i].name || ""
    for (var j = peerRows.count - 1; j >= 0; j--) {
      var mac = peerRows.get(j).mac
      if (!(mac in want)) {
        peerRows.remove(j)
      } else {
        if (peerRows.get(j).name !== want[mac]) peerRows.setProperty(j, "name", want[mac])
        delete want[mac]
      }
    }
    for (var k = 0; k < namedPeers.length; k++) {
      var p = namedPeers[k]
      if (p.mac in want) peerRows.append({ mac: p.mac, name: want[p.mac] })
    }
  }

  function mergePeers(list) {
    var out = []
    for (var i = 0; i < list.length; i++) {
      var p = list[i]
      out.push({ mac: p.mac, rssi: p.rssi, name: p.name || peerNames[p.mac] || "" })
    }
    peers = out
  }

  // One peer's answer, as the lookup reports it. The lookup streams a line
  // per peer the moment it answers, so a name appears seconds after it
  // arrives rather than when the slowest peer gives up half a minute later,
  // and closing the panel mid-lookup keeps every name already reported.
  function learnName(p) {
    if (!p || !p.mac || !p.name) return
    if (peerNames[p.mac] !== p.name) {
      var known = Object.assign({}, peerNames)
      known[p.mac] = p.name
      peerNames = known
      mergePeers(peers)
    }
    namesResolved = true
  }

  // A row flashes once, the first time its device appears in the list. A
  // device that leaves and comes back gets a new row, so "first time" has to
  // be remembered here rather than inferred from the row being created.
  function claimFlash(mac) {
    if (flashedMacs[mac]) return false
    var f = Object.assign({}, flashedMacs)
    f[mac] = true
    flashedMacs = f
    return true
  }

  function openRadar() {
    radarOpen = !radarOpen
    // Scanning is what a window does, so opening the radar on a machine that
    // is off opens one, for as long as the slider says.
    if (radarOpen && usable && !receiving && !busy) toggleOmdrop()
  }

  Process {
    id: peersProc
    command: [root.cli, "peers", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try { root.mergePeers(JSON.parse(text)) } catch (e) {}
      }
    }
  }

  // ------------------------------------------------------------ known senders
  //
  // The Contacts Only allow-list, edited through `omdrop senders`. The
  // receiver rereads the file on every request, so a change applies to the
  // next transfer with no restart.
  property bool sendersOpen: false
  property var senderList: []      // identifiers exactly as stored
  property string senderError: ""

  Process {
    id: sendersListProc
    command: [root.cli, "senders", "list", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try { root.senderList = JSON.parse(text) } catch (e) {}
      }
    }
  }
  function refreshSenders() {
    if (!sendersListProc.running) sendersListProc.running = true
  }
  function toggleSenders() {
    sendersOpen = !sendersOpen
    senderError = ""
    if (sendersOpen) refreshSenders()
  }

  // The CLI validates, so the panel shows its sentence rather than keeping a
  // second copy of the rules.
  Process {
    id: sendersEditProc
    property bool clearField: false
    stderr: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.senderError = text.trim().replace(/^omdrop: /, "")
    }
    onExited: function(code) {
      if (code === 0) {
        root.senderError = ""
        if (clearField) senderField.text = ""
      }
      root.refreshSenders()
      root.refreshStatus()
    }
  }
  function addSender(id) {
    id = id.trim()
    if (id === "" || sendersEditProc.running) return
    sendersEditProc.clearField = true
    sendersEditProc.command = [root.cli, "senders", "add", id]
    sendersEditProc.running = true
  }
  function removeSender(id) {
    if (sendersEditProc.running) return
    sendersEditProc.clearField = false
    sendersEditProc.command = [root.cli, "senders", "remove", id]
    sendersEditProc.running = true
  }

  Timer {
    interval: 2000
    repeat: true
    running: root.scanning
    triggeredOnStart: true
    onTriggered: if (!peersProc.running) peersProc.running = true
  }

  Process {
    id: namesProc
    command: [root.cli, "peers", "--json", "-n", "--stream"]
    property double startedAt: 0
    onStarted: startedAt = Date.now()
    stdout: SplitParser {
      onRead: function(line) {
        try { root.learnName(JSON.parse(line)) } catch (e) {}
      }
    }
    // A lookup that fails at once (no sender, the radio just went) would
    // otherwise restart in a tight loop, so a quick exit waits before the next.
    // A lookup that ran to its end has answered, names or not, so the
    // "resolving" line goes.
    onExited: {
      namesAgain.interval = Date.now() - startedAt < 5000 ? 10000 : 250
      if (Date.now() - startedAt >= 5000) root.namesResolved = true
    }
  }

  Timer {
    id: namesAgain
    interval: 250
    repeat: true
    running: root.scanning && !namesProc.running
    triggeredOnStart: true
    onTriggered: if (!namesProc.running) namesProc.running = true
  }

  // A radar that has been closed should not keep broadcasting.
  onScanningChanged: if (!scanning && namesProc.running) namesProc.signal(15)

  Process { id: soundProc; onExited: root.refreshStatus() }
  function toggleSound() {
    soundOn = !soundOn
    soundProc.command = [root.cli, "sound", soundOn ? "on" : "off"]
    soundProc.running = true
  }

  // Saved, not per-window: the receiver reads it on every request, and the CLI
  // restarts a running receiver so the change takes effect now. The tab flips
  // straight away; the poll after the CLI exits is what confirms it.
  Process { id: audienceProc; onExited: root.refreshStatus() }
  function setAudience(mode) {
    if (mode === audience || audienceProc.running) return
    audience = mode
    audienceProc.command = [root.cli, "visibility", mode]
    audienceProc.running = true
  }

  // ---------------------------------------------------------------- sending
  //
  // One send at a time, owned by the panel so it survives the popup closing
  // while the chooser has focus. The CLI opens the chooser where the last
  // file came from, remembers the folder, and narrates the transfer one line
  // at a time; the newest line is the row's status.
  //
  // The chooser takes the keyboard, and the panel closes when it loses it. So
  // the panel reopens as soon as the chooser answers -- with a file, to show
  // the transfer, or with a cancel, to put the person back where they were --
  // and closes on its own only after a file has arrived. A failure stays on
  // the row until the next attempt, so it can be read and retried.
  property string sendingTo: ""
  property string sendingName: ""
  property string sendStatus: ""
  property bool sendChosen: false    // the chooser answered with files
  property bool sendFailed: false
  property bool sendDone: false
  property bool sendCancelled: false
  property string sendingFile: ""    // "photo.jpg" or "3 files", from "Preparing …"

  // The CLI stops the sender's whole process group on TERM, so nothing goes
  // on knocking on the device's door after this.
  function cancelSend() {
    if (!sendProc.running) return
    sendCancelled = true
    sendStatus = "Cancelling…"
    sendProc.signal(15)
  }

  // A failure stays on the row until it has been read; this puts the row back.
  function dismissSend() {
    if (sendProc.running) return
    sendFailed = false
    sendingTo = ""
    sendStatus = ""
  }
  readonly property bool sendActive: sendProc.running && sendChosen

  function sendTo(mac) {
    if (sendProc.running) return
    var named = peers.filter(function(p) { return p.mac === mac })
    sendingTo = mac
    sendingName = named.length ? named[0].name : ""
    sendStatus = "Choose files…"
    sendChosen = false
    sendFailed = false
    sendDone = false
    sendingFile = ""
    sendClose.stop()
    sendProc.command = [root.cli, "send", "--pick", "--to", mac]
    sendProc.running = true
    root.close()   // out of the chooser's way; back when it answers
  }

  Process {
    id: sendProc
    stdout: SplitParser {
      onRead: function(line) {
        line = line.trim()
        if (line === "") return
        if (!root.sendChosen) { root.sendChosen = true; root.open() }
        var chosen = /^Preparing (.*)\.\.\.$/.exec(line)
        if (chosen) root.sendingFile = chosen[1]
        root.sendStatus = line
      }
    }
    // Line by line, like stdout: the sender says it is waiting while the
    // device's receiver wakes, which is progress worth seeing, and its last
    // line is the reason a failure failed. Keeping only the first line showed
    // the wait as if it were the outcome.
    stderr: SplitParser {
      onRead: function(line) {
        line = line.trim()
        if (line === "") return
        // The sender speaks of ports and paths ("waiting up to 30s for <mac>
        // to start listening on 8770", then "sending /full/path to <mac> at
        // [fe80::…]:8770"); from here both are simply the file on its way.
        var sending = /^sending (.*) to \S+ at /.exec(line)
        if (sending || /^waiting up to \d+s for .* to start listening/.test(line)) {
          var file = root.sendingFile || (sending ? sending[1].replace(/^.*\//, "") : "the file")
          line = "Sending " + file + " to "
              + (root.peerNames[root.sendingTo] || root.sendingName || root.sendingTo) + "..."
        }
        root.sendStatus = line
      }
    }
    onExited: function(code) {
      root.open()
      // A cancelled chooser is exit 1 with nothing said: no send, no message.
      // A send the person cancelled is not a failure either; the row just
      // goes back to being a row.
      if (root.sendCancelled
          || (code !== 0 && !root.sendChosen && root.sendStatus === "Choose files…")) {
        root.sendCancelled = false
        root.sendingTo = ""
        root.sendStatus = ""
        return
      }
      root.sendFailed = code !== 0
      root.sendDone = code === 0
      if (root.sendDone) sendClose.restart()
    }
  }

  // Long enough to read "Sent photo.jpg", then out of the way.
  Timer {
    id: sendClose
    interval: 1800
    onTriggered: {
      root.sendingTo = ""
      root.sendStatus = ""
      root.sendDone = false
      root.close()
    }
  }

  // Every change asks for a fresh status, and a request that arrives while a
  // poll is already running is queued, not dropped. Setting `running` on a
  // Process that is already running does nothing, so a poll that began before
  // the change finished after it and painted the old download folder back,
  // until the next timed poll up to ten seconds later. The in-flight answer
  // predates the change, so it is discarded rather than shown.
  property bool statusStale: false
  function refreshStatus() {
    if (statusProc.running) statusStale = true
    else statusProc.running = true
  }

  Process {
    id: statusProc
    command: [root.cli, "status", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: if (!root.statusStale) root.applyStatus(text)
    }
    onExited: function(code) {
      if (root.statusStale) {
        root.statusStale = false
        statusProc.running = true
        return
      }
      if (code !== 0) root.installed = false
    }
  }

  // "Not available" is the entire first-run experience for anyone who installs
  // the plugin before the driver package, and it explains nothing. The CLI
  // already knows exactly which piece is absent, in a sentence written for
  // someone holding a laptop; ask it, and say that instead.
  //
  // Recheck while off: packages, the radio backend and its prerequisites can
  // change outside this panel. A running receiver does not need this check.
  property string doctorText: ""
  property bool driverInstallable: false
  Process {
    id: doctorProc
    command: [root.cli, "doctor", "--json"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var d = JSON.parse(text)
          var missing = d.missing || []
          root.doctorText = missing.length ? missing[0].say : ""
          // Both are installed by the same press: the driver is a package to
          // build, the library a repository package the receiver imports.
          root.driverInstallable = missing.some(function(m) {
            return m.id === "driver" || m.id === "library"
          })
        } catch (e) {
          root.doctorText = ""
          root.driverInstallable = false
        }
      }
    }
  }

  // Fire and forget: the terminal it opens is the user interface from here on,
  // and re-asking doctor when it exits catches the case where they installed.
  Process {
    id: installDriverProc
    command: [root.cli, "install-driver"]
    onExited: { root.doctorText = ""; root.refreshStatus() }
  }

  function applyStatus(text) {
    try {
      var s = JSON.parse(text)
      installed = true
      receiving = !!s.receiving
      visibility = (s.visible === null || s.visible === undefined) ? -1 : (s.visible ? 1 : 0)
      remaining = (s.remaining === null || s.remaining === undefined) ? -1 : s.remaining
      deviceName = s.name || ""
      downloadDir = s.dir || ""
      blockedReason = s.reason || ""
      syncWindowToRunning(s.mode || "off")
      if (!soundProc.running) soundOn = s.sound !== false
      if (!audienceProc.running) audience = s.visibility === "contacts" ? "contacts" : "everyone"
      senders = s.senders || 0
      if (!nameField.activeFocus) nameField.text = shownName
      // A helper being present does not mean its prerequisites are met.
      // Refresh even when an earlier check supplied an explanation; otherwise
      // installing a backend or changing networks leaves that answer cached.
      if (!receiving && !busy && !doctorProc.running) doctorProc.running = true
      if (receiving) { doctorText = ""; driverInstallable = false }
    } catch (e) {
      installed = false
    }
  }

  // Once a second while the panel is open so the countdown ticks; every ten
  // seconds otherwise, which is enough for the bar icon to notice a window
  // that closed on its own.
  // The countdown ticks locally. Asking the CLI once a second would spawn a
  // dozen processes a second for a number we can count ourselves.
  Timer {
    interval: 1000
    repeat: true
    running: root.countingDown
    onTriggered: {
      root.remaining--
      // Reaching zero is the moment the window ends, so stop showing it as
      // running: the timer unit is firing `omdrop off` right now, and waiting
      // for the next poll to notice leaves the switch sitting in the wrong
      // position -- which is exactly what it did.
      if (root.remaining <= 0) {
        root.remaining = -1
        root.receiving = false
        root.visibility = 0
        root.refreshStatus()
      }
    }
  }

  // The resync. Slower than the tick, and what notices a window that ended
  // somewhere else -- an expiry we did not predict, or someone running
  // `omdrop off` in a terminal.
  Timer {
    interval: root.opened ? 3000 : 10000
    repeat: true
    running: true
    triggeredOnStart: true
    // A timed poll changes nothing, so one already in flight answers it.
    onTriggered: if (!statusProc.running) statusProc.running = true
  }

  // Opening the panel should show the truth immediately, not up to ten
  // seconds of whatever was true when it was last closed.
  //
  // Send to peers opens only when asked, so it collapses whenever the panel
  // closes -- except when the panel has only stepped aside for a chooser,
  // which it does mid-send and comes back from with the send's row showing.
  onOpenedChanged: {
    if (opened && !busy) root.refreshStatus()
    if (!opened && !sendProc.running && !pickingDir) radarOpen = false
  }

  IpcHandler {
    target: root.ipcTarget
    function toggle(): string { root.toggleOmdrop(); return "ok" }
    function status(): string { return root.stateText }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    iconComponent: Component {
      Item {
        OmdropIcon {
          anchors.centerIn: parent
          iconSize: Style.space(12)
          color: root.barIconColor
          crossed: !root.usable
          drifting: root.busy || root.settling
        }
      }
    }
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.RightButton) root.toggleOmdrop()
      else root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(300))
    contentHeight: panel.fittedContentHeight(column.implicitHeight)

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      // The catcher sees keys before its descendants, so while a text field
      // is being typed into it must stand aside: otherwise Enter and Space
      // toggle Omdrop, d and n act, and h/j/k/l/x never reach the field.
      blocked: nameField.activeFocus || senderField.activeFocus
      onCloseRequested: root.controller.hide()
      onActivateRequested: root.toggleOmdrop()
      onTextKey: function(t) {
        if (t === "d" || t === "D") root.toggleOmdrop()
        else if (t === "n" || t === "N") root.openRadar()
      }

      Column {
        id: column
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        spacing: Style.space(12)

        Item {
          width: parent.width
          implicitHeight: Math.max(heroIcon.implicitHeight, heroLabels.implicitHeight, heroSwitch.implicitHeight)

          OmdropIcon {
            id: heroIcon
            iconSize: Style.font.display
            color: root.busy || root.receiving ? root.foreground : root.dim
            crossed: !root.usable
            drifting: root.busy || root.settling
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
          }

          ToggleSwitch {
            id: heroSwitch
            visible: root.usable
            checked: root.receiving
            busy: root.busy
            foreground: root.foreground
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            onToggled: root.toggleOmdrop()
          }

          Column {
            id: heroLabels
            anchors.left: heroIcon.right
            anchors.leftMargin: Style.space(14)
            anchors.right: parent.right
            anchors.rightMargin: heroSwitch.visible ? heroSwitch.width + Style.space(12) : 0
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(2)

            Text {
              width: parent.width
              text: root.stateText
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.title
              font.bold: true
              elide: Text.ElideRight
            }

            Text {
              width: parent.width
              visible: root.countdownText !== ""
              text: root.countdownText
              color: Qt.darker(root.foreground, 1.4)
              font.family: root.fontFamily
              font.pixelSize: Style.font.caption
              font.bold: true
              font.letterSpacing: 1.2
            }
          }
        }

        PanelSeparator { foreground: root.foreground }

        Text {
          width: parent.width
          visible: text !== ""
          text: root.detailText
          color: root.detailUrgent ? root.urgent : Qt.darker(root.foreground, 1.5)
          font.family: root.fontFamily
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
        }

        // The one thing a first run can act on from here. Everything else
        // doctor reports is either a command (`omdrop setup`) or a restart, so
        // only the missing driver gets a button -- and it opens a terminal
        // rather than installing anything quietly. Installing a kernel module
        // is the user's decision, taken at their own sudo prompt.
        Button {
          visible: root.driverInstallable
          text: "Install the Wi-Fi driver"
          bordered: true
          foreground: root.foreground
          onClicked: installDriverProc.running = true
        }

        PanelSeparator { visible: root.usable; foreground: root.foreground }

        // How long a press of the switch keeps us visible. Both ends are
        // modes: the floor stops after one file arrives, the ceiling never
        // stops on its own.
        Column {
          visible: root.usable
          width: parent.width
          spacing: Style.space(8)

          Item {
            width: parent.width
            implicitHeight: Math.max(windowHeader.implicitHeight, windowValue.implicitHeight)

            PanelSectionHeader {
              id: windowHeader
              text: "STAY VISIBLE FOR"
              foreground: root.foreground
              fontFamily: root.fontFamily
              anchors.left: parent.left
              anchors.verticalCenter: parent.verticalCenter
            }

            Text {
              id: windowValue
              text: root.windowValueText
              // Under a minute it goes urgent: the last stretch is when you
              // care whether to press again.
              color: root.countingDown && root.remaining <= 60 ? root.urgent : root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              font.bold: root.countingDown
              anchors.right: parent.right
              anchors.verticalCenter: parent.verticalCenter

              Behavior on color { ColorAnimation { duration: 200 } }
            }
          }

          PanelSlider {
            width: parent.width
            bar: root.bar
            minimum: 0
            maximum: root.windowStops.length - 1
            step: 1
            integer: true
            tickCount: root.windowStops.length
            value: root.windowIndex
            onMoved: function(v) { root.windowPicking = true; root.windowIndex = Math.round(v) }
            onReleased: function(v) {
              root.windowIndex = Math.round(v)
              root.windowPicking = false
              root.rescheduleWindow()
            }
          }
        }

        // Who may send. Shown while Omdrop is off too, so the choice can be
        // made before a window opens rather than a few seconds into one. It is
        // saved, and applies to every window until changed.
        PanelSeparator { visible: root.usable; foreground: root.foreground }

        Item {
          visible: root.usable
          width: parent.width
          implicitHeight: Math.max(audienceTabs.implicitHeight, sendersButton.implicitHeight)

          Row {
            id: audienceTabs
            spacing: Style.space(22)
            anchors.verticalCenter: parent.verticalCenter

            // nf-md-account_multiple (U+F000E) and nf-md-account_circle
            // (U+F0009), written as surrogate pairs.
            AudienceTab {
              glyph: "\uDB80\uDC0E"
              label: "EVERYONE"
              selected: root.audience === "everyone"
              onChosen: root.setAudience("everyone")
            }
            AudienceTab {
              glyph: "\uDB80\uDC09"
              label: "CONTACTS ONLY"
              selected: root.audience === "contacts"
              onChosen: root.setAudience("contacts")
            }
          }

          // Opens the known-senders list. The count sits beside the icon in
          // the same dark colour, and is left out while the list is empty.
          Item {
            id: sendersButton
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            implicitWidth: sendersRow.implicitWidth
            implicitHeight: sendersRow.implicitHeight + Style.space(4)
            width: implicitWidth
            height: implicitHeight
            readonly property color tint: root.sendersOpen || sendersMouse.containsMouse
                                          ? root.foreground : Qt.darker(root.foreground, 2.0)

            Row {
              id: sendersRow
              anchors.verticalCenter: parent.verticalCenter
              spacing: Style.space(3)
              Text {
                // nf-md-account_multiple_plus (U+F0010)
                text: "\uDB80\uDC10"
                color: sendersButton.tint
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
                anchors.verticalCenter: parent.verticalCenter
              }
              Text {
                visible: root.senders > 0
                text: root.senders
                color: sendersButton.tint
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
                font.bold: true
                anchors.verticalCenter: parent.verticalCenter
              }
            }

            MouseArea {
              id: sendersMouse
              anchors.fill: parent
              anchors.margins: -Style.space(4)
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: root.toggleSenders()
            }

            PanelToolTip {
              visible: sendersMouse.containsMouse
              text: "Known senders, for Contacts Only"
              fontFamily: root.fontFamily
            }
          }
        }

        // The known-senders list, opened from the button above.
        Column {
          visible: root.usable && root.sendersOpen
          width: parent.width
          spacing: Style.space(2)

          Repeater {
            model: root.senderList
            delegate: Item {
              id: senderRow
              required property string modelData
              width: parent.width
              implicitHeight: senderText.implicitHeight + Style.space(10)

              Rectangle {
                anchors.fill: parent
                visible: senderMouse.containsMouse
                color: Style.hoverFillFor(root.foreground, Commons.Color.accent)
              }
              Text {
                id: senderText
                anchors.left: parent.left
                anchors.leftMargin: Style.space(10)
                anchors.right: removeGlyph.left
                anchors.verticalCenter: parent.verticalCenter
                text: senderRow.modelData
                textFormat: Text.PlainText
                elide: Text.ElideRight
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }
              Text {
                id: removeGlyph
                anchors.right: parent.right
                anchors.rightMargin: Style.space(10)
                anchors.verticalCenter: parent.verticalCenter
                text: "×"
                color: senderMouse.containsMouse ? root.foreground : root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.body
              }
              MouseArea {
                id: senderMouse
                anchors.fill: parent
                hoverEnabled: true
                cursorShape: Qt.PointingHandCursor
                onClicked: root.removeSender(senderRow.modelData)
              }
              PanelToolTip {
                visible: senderMouse.containsMouse
                text: "Remove " + senderRow.modelData
                fontFamily: root.fontFamily
              }
            }
          }

          TextField {
            id: senderField
            width: parent.width
            foreground: root.foreground
            placeholderText: "Apple ID email or phone number"
            onTextEdited: root.senderError = ""
            onAccepted: root.addSender(text)
            Keys.onEscapePressed: keyCatcher.forceActiveFocus()
          }

          Text {
            width: parent.width
            visible: root.senderError !== ""
            text: root.senderError
            color: root.urgent
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
            topPadding: Style.space(4)
          }

          Text {
            width: parent.width
            visible: root.senderList.length === 0 && root.senderError === ""
            text: "In Contacts Only, only these people can send to you. Use the email or phone number of their Apple ID."
            color: Qt.darker(root.foreground, 1.5)
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            wrapMode: Text.WordWrap
            topPadding: Style.space(4)
          }
        }

        PanelSeparator { visible: root.usable; foreground: root.foreground }

        // Sending. A header that opens downwards onto the radar, the
        // newest name it has learnt, and the devices that can be sent to.
        Item {
          visible: root.usable
          width: parent.width
          implicitHeight: nearbyHeader.implicitHeight + Style.space(4)

          PanelSectionHeader {
            id: nearbyHeader
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            text: "SEND TO PEERS"
            foreground: root.foreground
            fontFamily: root.fontFamily
          }

          Text {
            anchors.right: chevron.left
            anchors.rightMargin: Style.space(8)
            anchors.verticalCenter: parent.verticalCenter
            visible: !root.radarOpen && root.namedPeers.length > 0
            text: root.namedPeers.length + (root.namedPeers.length === 1 ? " device" : " devices")
            color: root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
          }

          Text {
            id: chevron
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            text: "\uf078"
            rotation: root.radarOpen ? 180 : 0
            color: nearbyMouse.containsMouse ? root.foreground : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.caption
            Behavior on rotation { NumberAnimation { duration: 180; easing.type: Easing.OutCubic } }
          }

          MouseArea {
            id: nearbyMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: root.openRadar()
          }
        }

        Item {
          id: radarDrawer
          visible: root.usable && height > 0
          width: parent.width
          height: root.radarOpen ? radarColumn.implicitHeight : 0
          clip: true
          Behavior on height { NumberAnimation { duration: 260; easing.type: Easing.OutCubic } }

          Column {
            id: radarColumn
            width: parent.width
            spacing: Style.space(10)

            // What the radar is doing, until there is nothing left to say:
            // searching until a device is heard, resolving until the first
            // name lookup has answered, then gone.
            //
            // The words stay still and only the dots move: the sentence is
            // centred as if it always carried three dots, and the dots grow to
            // its right in their own Text. Centring the whole string instead
            // shifted every word left and right as the dots changed.
            Item {
              width: parent.width
              visible: root.radarWorking
              implicitHeight: statusWords.implicitHeight

              TextMetrics {
                id: threeDots
                font: statusWords.font
                text: "..."
              }

              Text {
                id: statusWords
                x: Math.max(0, Math.round((parent.width - implicitWidth - threeDots.advanceWidth) / 2))
                textFormat: Text.PlainText
                text: root.radarStatus
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
              }

              Text {
                anchors.left: statusWords.right
                anchors.baseline: statusWords.baseline
                textFormat: Text.PlainText
                text: root.radarDots
                color: root.dim
                font: statusWords.font
              }
            }

            // The devices that can be sent to, first under the heading, where a
            // new one is seen the moment it arrives.
            Repeater {
              model: peerRows
              delegate: PeerRow {
                required property string mac
                required property string name
                width: radarColumn.width
                peer: ({ mac: mac, name: name })
              }
            }

            PanelSeparator {
              visible: root.namedPeers.length > 0
              width: parent.width
              foreground: root.foreground
            }

            Radar {
              anchors.horizontalCenter: parent.horizontalCenter
              width: Math.min(parent.width, Style.space(220))
              peers: root.peers
              scanning: root.scanning
              muted: !root.soundOn
              foreground: root.foreground
              fontFamily: root.fontFamily
              soundDir: Qt.resolvedUrl("share/sounds").toString().replace("file://", "")
              onMuteToggled: root.toggleSound()
              onPeerClicked: function(mac) { root.sendTo(mac) }
            }
          }
        }

        PanelSeparator { visible: root.usable; foreground: root.foreground }

        Column {
          visible: root.usable
          width: parent.width
          spacing: Style.space(8)

          PanelSectionHeader {
            text: "THEY SEE YOU AS"
            foreground: root.foreground
            fontFamily: root.fontFamily
          }

          TextField {
            id: nameField
            width: parent.width
            foreground: root.foreground
            text: root.shownName
            // Don't fight the user's typing: the polled name is only taken
            // back while this field is not being edited. Leaving the field
            // keeps what was typed, the same as Enter.
            onActiveFocusChanged: if (!activeFocus) {
              root.setDeviceName(text)
              text = root.shownName
            }
            onAccepted: root.setDeviceName(text)
            // Escape abandons the edit and hands the keys back to the panel.
            Keys.onEscapePressed: {
              text = root.shownName
              keyCatcher.forceActiveFocus()
            }
          }
        }

        Column {
          visible: root.usable
          width: parent.width
          spacing: Style.space(8)

          PanelSectionHeader {
            text: "SAVE FILES TO"
            foreground: root.foreground
            fontFamily: root.fontFamily
          }

          // The folder, shown as a button that opens it in the chooser.
          Button {
            width: parent.width
            leftAlign: true
            bordered: true
            foreground: root.foreground
            fontFamily: root.fontFamily
            fontSize: Style.font.bodySmall
            iconText: "\uf07c"
            text: root.pickingDir ? "Choosing in Files…" : root.tildify(root.downloadDir)
            tooltipText: "Choose another folder"
            onClicked: root.pickDownloadDir()
          }
        }
      }
    }
  }

  // A device that can be sent to: its name, its address, and the progress of
  // a send while one is going to it. Clicking it opens the chooser.
  component PeerRow: CursorSurface {
    id: row
    required property var peer
    readonly property bool target: root.sendingTo === peer.mac

    foreground: root.foreground
    implicitHeight: rowText.implicitHeight + Style.spacing.rowPaddingX

    // A flash that fades, the first time this device's name appears, so a
    // new arrival is noticed without looking for it.
    Rectangle {
      id: flash
      anchors.fill: parent
      radius: Style.space(4)
      color: root.foreground
      opacity: 0

      SequentialAnimation {
        id: flashAnim
        NumberAnimation { target: flash; property: "opacity"; to: 0.45; duration: 120; easing.type: Easing.OutQuad }
        NumberAnimation { target: flash; property: "opacity"; to: 0; duration: 1400; easing.type: Easing.InQuad }
      }
    }
    Component.onCompleted: if (root.claimFlash(peer.mac)) flashAnim.start()

    Column {
      id: rowText
      z: 1   // above the row's MouseArea, so the cancel button gets its clicks
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.leftMargin: Style.spacing.controlPaddingX
      anchors.rightMargin: Style.spacing.controlPaddingX
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(2)

      Item {
        width: parent.width
        implicitHeight: nameText.implicitHeight

        Text {
          id: nameText
          anchors.left: parent.left
          anchors.right: macText.left
          anchors.rightMargin: Style.space(8)
          textFormat: Text.PlainText
          // A device with no name yet is called by its address.
          text: row.peer.name || row.peer.mac
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
          font.bold: row.target
          elide: Text.ElideRight
        }

        Text {
          id: macText
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          visible: row.peer.name !== ""
          text: row.peer.mac
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
        }
      }

      // The status, with a way out: while a send is under way, an × to its
      // right cancels it -- the wait for a sleeping device can run 30 s.
      Item {
        width: parent.width
        visible: row.target && root.sendStatus !== ""
        implicitHeight: Math.max(statusText.implicitHeight, cancelButton.visible ? cancelButton.height : 0)

        Text {
          id: statusText
          anchors.left: parent.left
          anchors.right: cancelButton.visible ? cancelButton.left : parent.right
          anchors.rightMargin: cancelButton.visible ? Style.space(6) : 0
          textFormat: Text.PlainText
          text: root.sendStatus
          color: root.sendFailed ? root.urgent : Qt.darker(root.foreground, 1.3)
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          wrapMode: Text.WordWrap
        }

        Rectangle {
          id: cancelButton
          // Cancels a send under way; dismisses a failure once it is read.
          visible: root.sendActive || (root.sendFailed && !sendProc.running)
          anchors.right: parent.right
          anchors.top: parent.top
          width: Style.space(20); height: width
          radius: width / 2
          color: cancelMouse.containsMouse ? Style.hoverFillFor(root.foreground, Commons.Color.accent) : "transparent"

          Text {
            anchors.centerIn: parent
            text: "×"
            color: cancelMouse.containsMouse ? root.foreground : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.body
          }

          MouseArea {
            id: cancelMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: root.sendFailed ? root.dismissSend() : root.cancelSend()
          }

          PanelToolTip {
            visible: cancelMouse.containsMouse
            text: root.sendFailed ? "Dismiss" : "Cancel the send"
            fontFamily: root.fontFamily
          }
        }
      }

      // Progress, honestly: the sender reports stages (asked, accepted, sent)
      // and no byte counts, so while a transfer runs the bar says "working"
      // with a sliding segment rather than inventing a percentage. It fills
      // when the file has arrived.
      Rectangle {
        id: track
        visible: row.target && (root.sendActive || root.sendDone)
        width: parent.width
        height: Style.space(3)
        radius: height / 2
        color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15)
        clip: true

        Rectangle {
          id: segment
          visible: root.sendActive
          height: parent.height
          radius: parent.radius
          color: root.foreground
          width: track.width * 0.3

          NumberAnimation on x {
            running: segment.visible && track.visible
            loops: Animation.Infinite
            from: -segment.width; to: track.width
            duration: 1100; easing.type: Easing.InOutQuad
          }
        }

        Rectangle {
          visible: root.sendDone
          anchors.fill: parent
          radius: parent.radius
          color: root.foreground
        }
      }
    }

    MouseArea {
      id: rowMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: sendProc.running ? Qt.BusyCursor : Qt.PointingHandCursor
      onContainsMouseChanged: row.hasCursor = containsMouse
      onClicked: root.sendTo(row.peer.mac)
    }

    PanelToolTip {
      visible: rowMouse.containsMouse && !sendProc.running
      text: "Send a file to " + (row.peer.name || row.peer.mac)
      fontFamily: root.fontFamily
    }
  }
}
