pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Shapes
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui

Item {
  id: root
  property var peers: []
  property bool scanning: false
  property bool muted: false
  property color foreground: Commons.Color.foreground
  property string fontFamily: Style.font.family
  property string soundDir: ""
  signal muteToggled()
  signal peerClicked(string mac)

  implicitWidth: Style.space(260)
  implicitHeight: width
  readonly property bool active: visible && scanning
  readonly property real radius: Math.max(0, Math.min(width, height) / 2 - Style.space(8))
  property real sweepAngle: 0
  property var labelPositions: ({})
  property real previousSweepAngle: -1

  function advanceSweep() {
    var current = (sweepAngle + 360) % 360
    var previous = previousSweepAngle
    previousSweepAngle = current
    if (!active || previous < 0) return
    var travelled = (current - previous + 360) % 360
    if (travelled === 0) return
    for (var i = 0; i < contactRepeater.count; i++) {
      var contact = contactRepeater.itemAt(i)
      if (!contact || !contact.present) continue
      // Use the displayed dot, including an in-flight RSSI position animation.
      var angle = (Math.atan2(contact.x - width / 2, height / 2 - contact.y) * 180 / Math.PI + 360) % 360
      var distance = (angle - previous + 360) % 360
      if (distance > 0 && distance <= travelled) contact.sweepHit()
    }
  }

  onSweepAngleChanged: advanceSweep()

  // Run on snapshot/geometry/font changes, never on sweep frames.
  function layoutLabels() {
    if (!visible) return
    var ordered = []
    for (var i = 0; i < contactRepeater.count; i++) {
      var item = contactRepeater.itemAt(i)
      if (item && item.present && item.peerName !== "") ordered.push(item)
    }
    ordered.sort(function(a, b) {
      return b.strength - a.strength || Number(b.knownSignal) - Number(a.knownSignal)
          || (a.mac < b.mac ? -1 : a.mac > b.mac ? 1 : 0)
    })
    var placed = []
    var positions = {}
    var inset = Math.max(0, radius - Style.space(5))
    var gap = Style.space(9)
    var padX = Style.space(4)
    var padY = Style.space(3)
    for (var j = 0; j < ordered.length; j++) {
      var peer = ordered[j]
      var labelHeight = peer.labelHeight
      var preferred = peer.targetX > width / 2 ? -1 : 1
      var attempts = [[preferred, 0], [-preferred, 0],
                      [-preferred, labelHeight + padY * 2], [-preferred, -labelHeight - padY * 2]]
      for (var k = 0; k < attempts.length; k++) {
        var side = attempts[k][0]
        var top = Math.max(height / 2 - inset + labelHeight / 2,
                           Math.min(peer.targetY - labelHeight / 2 + attempts[k][1],
                                    height / 2 + inset - labelHeight * 1.5))
        var edgeY = Math.max(Math.abs(top - height / 2), Math.abs(top + labelHeight - height / 2))
        var halfChord = Math.sqrt(Math.max(0, inset * inset - edgeY * edgeY))
        var available = side > 0 ? width / 2 + halfChord - peer.targetX - gap
                                 : peer.targetX - gap - (width / 2 - halfChord)
        var labelWidth = Math.min(peer.labelWidth, width * 0.42, available)
        if (labelWidth < Math.min(peer.labelWidth, Style.space(24))) continue
        var left = side > 0 ? peer.targetX + gap : peer.targetX - gap - labelWidth
        var box = { x: left, y: top, width: labelWidth, height: labelHeight }
        var collides = placed.some(function(other) {
          return box.x - padX < other.x + other.width + padX
              && box.x + box.width + padX > other.x - padX
              && box.y - padY < other.y + other.height + padY
              && box.y + box.height + padY > other.y - padY
        })
        if (!collides) {
          positions[peer.mac] = box
          placed.push(box)
          break
        }
      }
    }
    labelPositions = positions
  }

  function angleFor(mac) {
    var hash = 0
    for (var i = 0; i < mac.length; i++) hash = (hash * 31 + mac.charCodeAt(i)) >>> 0
    return hash % 360
  }

  function removeDeparted() {
    for (var i = contacts.count - 1; i >= 0; i--)
      if (!contacts.get(i).present) contacts.remove(i)
    Qt.callLater(root.layoutLabels)
  }

  // Panel supplies a successful, merged snapshot. A failed poll must not become [].
  function reconcile() {
    var snapshot = peers || []
    var seen = {}
    var added = false
    for (var i = 0; i < snapshot.length; i++) {
      var peer = snapshot[i]
      if (!peer || typeof peer.mac !== "string" || !peer.mac) continue
      var mac = peer.mac.toLowerCase()
      if (seen[mac]) continue
      seen[mac] = true
      var known = typeof peer.rssi === "number" && isFinite(peer.rssi)
      var strength = known ? Math.max(0, Math.min(1, (peer.rssi + 90) / 60)) : 0
      var name = typeof peer.name === "string" ? peer.name : ""
      var found = -1
      for (var j = 0; j < contacts.count; j++) {
        if (contacts.get(j).mac === mac) { found = j; break }
      }
      // Sound belongs to devices that can be sent to: the blip marks a name
      // arriving, whether on a new dot or on one already drawn.
      if (found < 0) {
        contacts.append({ mac: mac, peerName: name, bearing: angleFor(mac), strength: strength,
                          knownSignal: known, present: true })
        if (name !== "") added = true
      } else {
        if (name !== "" && contacts.get(found).peerName === "") added = true
        contacts.set(found, { mac: mac, peerName: name, bearing: angleFor(mac), strength: strength,
                              knownSignal: known, present: true })
      }
    }
    var departed = false
    for (var k = 0; k < contacts.count; k++) {
      if (!seen[contacts.get(k).mac]) {
        contacts.setProperty(k, "present", false)
        departed = true
      }
    }
    if (departed && visible) departureTimer.restart()
    else if (!visible) removeDeparted()
    if (added) playSound("blip.wav", 0.55, "")
    Qt.callLater(root.layoutLabels)
  }

  // Three tracked voices; a saturated pool drops a crossing rather than delaying it.
  readonly property var voices: [voiceOne, voiceTwo, voiceThree]
  function playSound(filename, volume, mac) {
    if (!active || muted || !soundDir) return
    for (var i = 0; i < voices.length; i++) {
      var voice = voices[i]
      if (voice.running) continue
      voice.peerMac = mac
      voice.command = ["/bin/sh", "-c",
        'if command -v pw-play >/dev/null 2>&1; then exec pw-play --volume \"$2\" \"$1\"; elif command -v paplay >/dev/null 2>&1; then exec paplay --volume \"$3\" \"$1\"; fi',
        "omdrop-sound", soundDir + "/" + filename, String(volume), String(Math.round(volume * 65536))]
      voice.running = true
      return
    }
  }

  function stopContactSound(mac) {
    for (var i = 0; i < voices.length; i++)
      if (voices[i].peerMac === mac) voices[i].running = false
  }

  function stopSounds() {
    for (var v = 0; v < voices.length; v++) voices[v].running = false
    for (var i = 0; i < contactRepeater.count; i++) {
      var contact = contactRepeater.itemAt(i)
      if (contact) contact.quiet(!active)
    }
  }

  onPeersChanged: reconcile()
  onActiveChanged: {
    previousSweepAngle = -1
    if (!active) stopSounds()
  }
  onMutedChanged: if (muted) stopSounds()
  onWidthChanged: Qt.callLater(root.layoutLabels)
  onHeightChanged: Qt.callLater(root.layoutLabels)
  onRadiusChanged: Qt.callLater(root.layoutLabels)
  onVisibleChanged: {
    if (!visible) {
      departureTimer.stop()
      removeDeparted()
    } else Qt.callLater(root.layoutLabels)
  }
  Component.onCompleted: reconcile()
  Component.onDestruction: stopSounds()

  ListModel { id: contacts }
  Timer { id: departureTimer; interval: 240; onTriggered: root.removeDeparted() }
  Process { id: voiceOne; property string peerMac: "" }
  Process { id: voiceTwo; property string peerMac: "" }
  Process { id: voiceThree; property string peerMac: "" }
  NumberAnimation on sweepAngle {
    from: 0; to: 360; duration: 4000; loops: Animation.Infinite
    running: root.active && !Style.reduceMotion
    onRunningChanged: root.previousSweepAngle = -1
  }

  Repeater {
    model: 3
    Rectangle {
      required property int index
      width: root.radius * 2 * (index + 1) / 3
      height: width
      radius: width / 2
      anchors.centerIn: parent
      color: "transparent"
      border.width: 1
      border.color: root.foreground
      opacity: 0.16
    }
  }
  Rectangle {
    anchors.centerIn: parent
    width: root.radius * 2; height: 1
    color: root.foreground; opacity: 0.10
  }
  Rectangle {
    anchors.centerIn: parent
    height: root.radius * 2; width: 1
    color: root.foreground; opacity: 0.10
  }
  Item {
    anchors.centerIn: parent
    width: root.radius * 2; height: width
    rotation: root.sweepAngle
    visible: root.scanning && !Style.reduceMotion
    Shape {
      anchors.fill: parent
      ShapePath {
        strokeWidth: 0
        strokeColor: "transparent"
        fillGradient: ConicalGradient {
          centerX: root.radius; centerY: root.radius
          // Gradients run counter-clockwise: this is behind the clockwise sweep.
          angle: 90
          GradientStop { position: 0; color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.25) }
          GradientStop { position: 0.08; color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.12) }
          GradientStop { position: 70 / 360; color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0) }
          GradientStop { position: 1; color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0) }
        }
        startX: root.radius; startY: 0
        PathArc { x: root.radius; y: root.radius * 2; radiusX: root.radius; radiusY: root.radius }
        PathArc { x: root.radius; y: 0; radiusX: root.radius; radiusY: root.radius }
      }
      ShapePath {
        strokeWidth: 1.5
        strokeColor: root.foreground
        fillColor: "transparent"
        startX: root.radius; startY: root.radius
        PathLine { x: root.radius; y: 0 }
      }
    }
  }

  Repeater {
    id: contactRepeater
    model: contacts
    delegate: Item {
      id: contact
      required property string mac
      required property string peerName
      required property real bearing
      required property real strength
      required property bool knownSignal
      required property bool present
      readonly property real labelWidth: label.implicitWidth
      readonly property real labelHeight: label.implicitHeight
      readonly property var labelPlacement: root.labelPositions[mac] || null
      readonly property real targetX: root.width / 2 + Math.sin(radians) * root.radius * radialFraction
      readonly property real targetY: root.height / 2 - Math.cos(radians) * root.radius * radialFraction
      Component.onCompleted: Qt.callLater(root.layoutLabels)
      readonly property bool hot: peerButton.enabled && (peerMouse.containsMouse || peerButton.activeFocus)
      z: hot ? 3 : peerName !== "" ? 2 : 1
      readonly property real radialFraction: knownSignal ? 0.92 - 0.74 * strength : 0.96
      readonly property real radians: bearing * Math.PI / 180
      property real flare: 0
      function sweepHit() {
        pulseDecay.stop()
        flare = 1
        pulseDecay.restart()
        // Every dot pulses; only named ones ping, so the sound marks the
        // devices you know rather than every radio in the room.
        if (peerName !== "")
          root.playSound("contact-" + (1 + Math.round(strength * 4)) + ".wav", 0.55 + 0.45 * strength, mac)
      }
      function quiet(clearPulse) {
        root.stopContactSound(mac)
        if (clearPulse) {
          pulseDecay.stop()
          flare = 0
        }
      }
      onPresentChanged: if (!present) quiet(true)
      Component.onDestruction: quiet(true)
      NumberAnimation {
        id: pulseDecay
        target: contact
        property: "flare"
        to: 0
        duration: Style.duration(600)
        easing.type: Easing.OutCubic
      }
      property real entrance: 0
      x: targetX
      y: targetY
      opacity: present ? entrance : 0
      scale: 0.65 + 0.35 * entrance
      Behavior on opacity { enabled: root.visible; NumberAnimation { duration: Style.duration(200) } }
      NumberAnimation on entrance { from: 0; to: 1; duration: Style.duration(220); running: root.visible }
      Behavior on x { enabled: root.visible; NumberAnimation { duration: Style.duration(400) } }
      Behavior on y { enabled: root.visible; NumberAnimation { duration: Style.duration(400) } }

      Rectangle {
        anchors.centerIn: parent
        width: Style.space(15) + contact.flare * Style.space(8)
        height: width; radius: width / 2
        color: root.foreground
        opacity: contact.knownSignal ? 0.06 + 0.16 * contact.flare : 0.03 + 0.10 * contact.flare
      }
      Rectangle {
        anchors.centerIn: parent
        width: Style.space(6); height: width; radius: width / 2
        color: root.foreground
        opacity: contact.hot ? 1 : contact.knownSignal ? Math.min(1, 0.35 + 0.5 * contact.strength + 0.4 * contact.flare) : 0.22 + 0.4 * contact.flare
      }
      Rectangle {
        x: label.x - Style.space(4); y: label.y - Style.space(3)
        width: label.width + Style.space(8); height: label.height + Style.space(6)
        radius: Style.space(4)
        visible: contact.hot && label.visible
        color: Style.hoverFillFor(root.foreground, Commons.Color.accent)
      }
      Text {
        id: label
        visible: contact.peerName !== "" && contact.labelPlacement !== null
        text: contact.peerName
        textFormat: Text.PlainText
        color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, contact.hot ? 1 : 0.72)
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        onImplicitWidthChanged: Qt.callLater(root.layoutLabels)
        onImplicitHeightChanged: Qt.callLater(root.layoutLabels)
        width: contact.labelPlacement ? contact.labelPlacement.width : 0
        elide: Text.ElideRight
        x: contact.labelPlacement ? contact.labelPlacement.x - contact.x : 0
        y: contact.labelPlacement ? contact.labelPlacement.y - contact.y : 0
      }
      Item {
        id: peerButton
        // Any dot can be sent to. A device need not have answered a name
        // lookup to accept a file, so its address is target enough.
        enabled: contact.present
        activeFocusOnTab: enabled && root.visible
        x: Math.min(-Style.space(14), label.x - Style.space(4))
        y: Math.min(-Style.space(14), label.y - Style.space(3))
        width: Math.max(Style.space(14), label.x + label.width + Style.space(4)) - x
        height: Math.max(Style.space(14), label.y + label.height + Style.space(3)) - y
        z: 1
        Accessible.role: Accessible.Button
        Accessible.name: "Send to " + (contact.peerName || contact.mac)
        Accessible.onPressAction: root.peerClicked(contact.mac)
        Keys.onReturnPressed: root.peerClicked(contact.mac)
        Keys.onSpacePressed: root.peerClicked(contact.mac)
        Rectangle {
          anchors.fill: parent
          visible: peerButton.activeFocus
          color: "transparent"
          border.color: root.foreground
        }
        MouseArea {
          id: peerMouse
          hoverEnabled: true
          anchors.fill: parent
          cursorShape: Qt.PointingHandCursor
          onClicked: root.peerClicked(contact.mac)
        }
        PanelToolTip {
          visible: root.visible && peerButton.enabled && peerMouse.containsMouse
          text: "Send a file to " + (contact.peerName || contact.mac)
          fontFamily: root.fontFamily
        }
      }
    }
  }

  // Quiet by design: a small outline in the bottom-right corner that stays
  // out of the scope's way, and only comes forward under the pointer.
  Item {
    id: muteButton
    width: Style.space(22); height: width
    anchors.bottom: parent.bottom; anchors.right: parent.right
    activeFocusOnTab: root.visible
    opacity: muteMouse.containsMouse || activeFocus ? 0.85 : 0.3
    Behavior on opacity { NumberAnimation { duration: Style.duration(150) } }
    Accessible.role: Accessible.Button
    Accessible.name: root.muted ? "Unmute radar sound" : "Mute radar sound"
    Accessible.onPressAction: root.muteToggled()
    Keys.onReturnPressed: root.muteToggled()
    Keys.onSpacePressed: root.muteToggled()
    Rectangle {
      anchors.fill: parent
      radius: width / 2
      color: "transparent"
      border.color: root.foreground
      border.width: muteButton.activeFocus ? 1 : 0
    }
    Shape {
      anchors.centerIn: parent
      width: 24; height: 24
      scale: muteButton.width / 24 * 0.7
      ShapePath {
        strokeColor: root.foreground; strokeWidth: 1.6; fillColor: "transparent"
        joinStyle: ShapePath.RoundJoin
        startX: 3; startY: 9.5
        PathLine { x: 7; y: 9.5 }
        PathLine { x: 12; y: 5.5 }
        PathLine { x: 12; y: 18.5 }
        PathLine { x: 7; y: 14.5 }
        PathLine { x: 3; y: 14.5 }
        PathLine { x: 3; y: 9.5 }
      }
      // One sound wave while on; a small cross where it was once muted.
      ShapePath {
        strokeColor: root.muted ? "transparent" : root.foreground
        strokeWidth: 1.6; fillColor: "transparent"; capStyle: ShapePath.RoundCap
        PathSvg { path: "M15.5 8.5a5 5 0 0 1 0 7" }
      }
      ShapePath {
        strokeColor: root.muted ? root.foreground : "transparent"
        strokeWidth: 1.6; fillColor: "transparent"; capStyle: ShapePath.RoundCap
        PathSvg { path: "M15.5 9.5l5 5M20.5 9.5l-5 5" }
      }
    }
    MouseArea {
      id: muteMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: root.muteToggled()
    }
  }
}
