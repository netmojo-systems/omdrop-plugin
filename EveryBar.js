.pragma library

var panels = []
var seenUntil = -1

function join(panel) {
  panels.push(panel)
  return seenUntil
}

function leave(panel) {
  panels = panels.filter(function(other) { return other !== panel })
}

function refreshReceived() {
  panels.forEach(function(panel) { panel.refreshReceived() })
}

function markSeenUntil(time) {
  if (time <= seenUntil) return
  seenUntil = time
  panels.forEach(function(panel) { panel.seenUntil = time })
}
