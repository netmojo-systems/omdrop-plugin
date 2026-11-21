import QtQuick
import QtQuick.Shapes
import qs.Commons
import qs.Commons as Commons

// A drop: a triangle pointing down into the box it lands in. Nothing in a Nerd
// Font draws this, and an SVG asset would not follow the bar's foreground
// colour, so it is a Shape authored on a 24 grid and scaled to whatever the
// caller asks for. The triangle is filled so it keeps its weight beside the
// bar's glyph icons at 12 px, where a stroked outline thins to a hairline.
Item {
  id: root

  property color color: Commons.Color.foreground
  property real iconSize: Style.font.icon
  property bool crossed: false

  // Drifting, while the radio gate runs. It sways and sinks rather than
  // spinning: the wait is 15-60s and a spinner that long reads as a hang,
  // where drift reads as travel.
  property bool drifting: false

  implicitWidth: iconSize
  implicitHeight: iconSize

  Item {
    anchors.centerIn: parent
    width: 24
    height: 24
    scale: root.iconSize / 24

    // verticalCenterOffset, not y: the item is anchored with centerIn, and an
    // animation on y silently loses to the anchor. Two loops of different
    // length, so they never resolve together and it reads as drift. Each loop
    // ends back at rest, because alwaysRunToEnd finishes the loop in progress
    // when drifting stops: a loop ending at its far swing left the icon
    // tilted in the panel for as long as it stayed open.
    SequentialAnimation on anchors.verticalCenterOffset {
      running: root.drifting && !Style.reduceMotion
      loops: Animation.Infinite
      alwaysRunToEnd: true
      NumberAnimation { to: 1.6; duration: 750; easing.type: Easing.OutSine }
      NumberAnimation { to: -1.6; duration: 1500; easing.type: Easing.InOutSine }
      NumberAnimation { to: 0; duration: 750; easing.type: Easing.InSine }
    }

    SequentialAnimation on rotation {
      running: root.drifting && !Style.reduceMotion
      loops: Animation.Infinite
      alwaysRunToEnd: true
      NumberAnimation { to: 4; duration: 950; easing.type: Easing.OutSine }
      NumberAnimation { to: -4; duration: 1900; easing.type: Easing.InOutSine }
      NumberAnimation { to: 0; duration: 950; easing.type: Easing.InSine }
    }

    Shape {
      anchors.fill: parent

      ShapePath {
        strokeColor: root.color
        fillColor: root.color
        strokeWidth: 1.7
        joinStyle: ShapePath.RoundJoin
        PathSvg { path: "M1.5 3.5h21L12 13.5z" }
      }

      ShapePath {
        strokeColor: root.color
        fillColor: "transparent"
        strokeWidth: 1.7
        capStyle: ShapePath.RoundCap
        joinStyle: ShapePath.RoundJoin
        PathSvg { path: "M8 16h8v5.5H8z" }
      }

      // Struck through while the radio support is missing. Kept as its own
      // path with a real `d` at all times -- an empty path string takes the
      // whole Shape down with it.
      ShapePath {
        strokeColor: root.crossed ? root.color : "transparent"
        fillColor: "transparent"
        strokeWidth: 1.7
        capStyle: ShapePath.RoundCap
        PathSvg { path: "M3 21 21 3" }
      }
    }
  }
}
