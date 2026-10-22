"""The toast for a received file: its thumbnail, and what a click opens.

An iPhone sends photos as HEIC, which the notification daemon cannot decode,
so the toast gets a small JPEG preview, kept in the runtime dir and pruned. A
click opens the file with its app, and shows it in the file manager only when
no app is registered for its type -- otherwise xdg-open picks the browser.
"""

import fcntl
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OMDROP = ROOT / "bin" / "omdrop"

# heif-convert SRC DEST, and magick SRC ... DEST: write something to DEST, and
# log the call. magick's DEST carries a jpg: prefix.
HEIF_CONVERT = 'printf "heif-convert|%s\\n" "$*" >> "$LOG"; for a; do d=$a; done; printf jpeg > "$d"'
MAGICK = 'printf "magick|%s\\n" "$*" >> "$LOG"; for a; do d=$a; done; printf small > "${d#jpg:}"'


class NotificationFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.log = self.root / "log"
        self.runtime = self.root / "run"
        self.runtime.mkdir()
        self.previews = self.runtime / "omdrop" / "previews"
        self.stub("uwsm-app", 'shift; exec "$@"')
        self.stub("nautilus", 'printf "nautilus|%s\\n" "$*" >> "$LOG"')
        self.stub("xdg-open", 'printf "xdg-open|%s\\n" "$*" >> "$LOG"')
        # The type comes from the extension; only MIME_DEFAULTS have an app.
        self.stub(
            "xdg-mime",
            'case "$2" in\n'
            '  filetype) case "$3" in *.heic) echo image/heic ;; *.jpg) echo image/jpeg ;; esac ;;\n'
            '  default) case " $MIME_DEFAULTS " in *" $3 "*) echo app.desktop ;; esac ;;\n'
            "esac",
        )
        self.stub("wl-copy", "cat >/dev/null")
        self.stub("omarchy-notification-send", 'printf "notify|%s\\n" "$*" >> "$LOG"')
        self.stub("heif-convert", HEIF_CONVERT)
        self.stub("magick", MAGICK)
        self.env = os.environ.copy()
        self.env.update(
            PATH=f"{self.bin}:{self.env['PATH']}",
            LOG=str(self.log),
            MIME_DEFAULTS="image/jpeg",
            XDG_CONFIG_HOME=str(self.root / "config"),
            XDG_DATA_HOME=str(self.root / "data"),
            XDG_CACHE_HOME=str(self.root / "cache"),
            XDG_RUNTIME_DIR=str(self.runtime),
        )

    def stub(self, name, body):
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)

    def run_omdrop(self, *args):
        return subprocess.run([OMDROP, *args], env=self.env, capture_output=True, text=True)

    def logged(self, prefix=""):
        lines = self.log.read_text().splitlines() if self.log.exists() else []
        return [line for line in lines if line.startswith(prefix)]

    def arrive(self, name):
        photo = self.root / name
        photo.write_bytes(b"photo")
        result = self.run_omdrop("handle", str(photo))
        self.assertEqual(result.returncode, 0, result.stderr)
        return photo

    def notified_image(self):
        """The --image of the last toast, or None when it has none."""
        words = self.logged("notify|")[-1].split()
        return Path(words[words.index("--image") + 1]) if "--image" in words else None


class ClickTests(NotificationFixture):
    def test_a_click_opens_a_file_that_has_an_app(self):
        photo = self.root / "photo.jpg"
        photo.write_bytes(b"jpeg")

        result = self.run_omdrop("act", "open", str(photo))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logged(), [f"xdg-open|{photo}"])

    def test_a_click_shows_a_file_without_an_app_in_the_file_manager(self):
        photo = self.root / "IMG_1.heic"
        photo.write_bytes(b"heic")

        result = self.run_omdrop("act", "open", str(photo))

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.logged(), [f"nautilus|--select {photo}"])

    def test_a_click_opens_a_heic_once_an_app_is_registered_for_it(self):
        self.env["MIME_DEFAULTS"] = "image/jpeg image/heic"
        photo = self.root / "IMG_1.heic"
        photo.write_bytes(b"heic")

        self.run_omdrop("act", "open", str(photo))

        self.assertEqual(self.logged(), [f"xdg-open|{photo}"])


class PreviewTests(NotificationFixture):
    def test_a_heic_toast_carries_a_small_preview_in_the_runtime_dir(self):
        self.arrive("IMG_1.heic")

        preview = self.notified_image()
        self.assertIsNotNone(preview)
        self.assertEqual(preview.parent, self.previews)
        self.assertEqual(preview.suffix, ".jpg")
        self.assertEqual(preview.read_bytes(), b"small")
        self.assertIn("-thumbnail 512x512>", self.logged("magick|")[0])
        self.assertFalse((self.root / "cache" / "omdrop").exists())

    def test_the_preview_stays_full_size_without_imagemagick(self):
        (self.bin / "magick").unlink()
        self.stub("magick", "exit 127")

        self.arrive("IMG_1.heic")

        self.assertEqual(self.notified_image().read_bytes(), b"jpeg")

    def test_previews_of_the_same_name_do_not_overwrite_each_other(self):
        self.arrive("IMG_1.heic")
        first = self.notified_image()
        self.arrive("IMG_1.avif")
        second = self.notified_image()

        self.assertNotEqual(first, second)
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())

    def test_only_the_newest_previews_are_kept(self):
        for n in range(12):
            self.arrive(f"IMG_{n}.heic")
            # Distinct mtimes, so the newest are unambiguous.
            time.sleep(0.01)

        kept = sorted(self.previews.iterdir())
        self.assertEqual(len(kept), 10)
        self.assertIn(self.notified_image(), kept)

    def test_a_preview_still_being_decoded_survives_other_arrivals(self):
        # Arrivals are handled in parallel. One photo's preview decodes slowly
        # while eleven others arrive and finish; their pruning must not delete
        # the file the slow decode has already written into.
        self.stub("heif-convert", HEIF_CONVERT + '\ncase "$3$4" in *SLOW*/omdrop/previews/*) sleep 2 ;; esac')
        slow = self.root / "SLOW.heic"
        slow.write_bytes(b"photo")
        decoding = subprocess.Popen([OMDROP, "handle", str(slow)], env=self.env,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        for n in range(11):
            self.arrive(f"IMG_{n}.heic")
            time.sleep(0.01)
        self.assertEqual(decoding.wait(timeout=30), 0)

        preview = self.notified_image()
        self.assertIsNotNone(preview, "the slow photo's toast lost its preview")
        self.assertTrue(preview.exists())

    def test_a_preview_whose_shrink_timed_out_survives_newer_previews(self):
        # A shrink that times out leaves the decode's older time on the
        # preview, and ten newer previews finish meanwhile; pruning must still
        # keep the preview this toast is about to show. Arrivals now decode
        # one at a time, so the newer previews are written here directly.
        self.stub("heif-convert",
                  'printf "heif-convert|%s\\n" "$*" >> "$LOG"; for a; do d=$a; done\n'
                  'case "$*" in *SLOW*) printf slow > "$d" ;; *) printf jpeg > "$d" ;; esac')
        self.stub("magick", 'case "$(cat "$1")" in slow) printf "magick|slow\\n" >> "$LOG"; exec sleep 30 ;; esac\n'
                  + MAGICK)
        slow = self.root / "SLOW.heic"
        slow.write_bytes(b"photo")
        decoding = subprocess.Popen([OMDROP, "handle", str(slow)],
                                    env=dict(self.env, OMDROP_PREVIEW_TIMEOUT="3"),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10
        while "magick|" not in (self.log.read_text() if self.log.exists() else ""):
            self.assertLess(time.monotonic(), deadline, "the slow shrink never started")
            time.sleep(0.05)
        for n in range(10):
            (self.previews / f"preview.Newer{n}.jpg").write_bytes(b"small")
            time.sleep(0.01)
        self.assertIsNone(decoding.poll(), "the slow shrink ended before the others finished")
        self.assertEqual(decoding.wait(timeout=30), 0)

        toast = [line for line in self.logged("notify|") if "SLOW.heic" in line][0].split()
        self.assertIn("--image", toast, "the slow photo's toast lost its preview")
        preview = Path(toast[toast.index("--image") + 1])
        self.assertTrue(preview.exists(), "pruned before its toast showed it")

    def test_a_preview_left_behind_by_a_killed_decode_is_cleaned_up(self):
        self.previews.mkdir(parents=True)
        stale = self.previews / "working.Old456.jpg"
        stale.write_bytes(b"half")
        old = time.time() - 600
        os.utime(stale, (old, old))

        self.arrive("IMG_9.heic")

        self.assertFalse(stale.exists())

    def test_a_heic_toast_still_appears_when_the_conversion_fails(self):
        self.stub("heif-convert", "exit 1")

        self.arrive("IMG_2.heic")

        self.assertEqual(len(self.logged("notify|")), 1)
        self.assertIsNone(self.notified_image())
        self.assertEqual(list(self.previews.iterdir()), [])

    def test_a_conversion_that_hangs_is_cut_off(self):
        # Only the preview's decode hangs. The clipboard's own HEIC-to-JPEG
        # decode (#62) has a fixed 10 s limit of its own, which this test
        # does not measure, so it fails at once.
        self.stub("heif-convert",
                  'case "$4" in */omdrop/previews/*) exec sleep 30 ;; esac\nexit 1')
        self.env["OMDROP_PREVIEW_TIMEOUT"] = "1"

        started = time.monotonic()
        self.arrive("IMG_3.heic")

        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(len(self.logged("notify|")), 1)
        self.assertIsNone(self.notified_image())

    def test_a_jpeg_toast_uses_the_file_itself(self):
        photo = self.arrive("photo.jpg")

        self.assertEqual(self.notified_image(), photo)
        self.assertEqual(self.logged("heif-convert|"), [])


class HeadlineTests(NotificationFixture):
    """The toast's headline is the name a sender chose. omarchy-notification-send
    reads options until its headline and has no `--`, so a name such as `-t`
    would be read as an option, and the toast lost or changed."""

    def argv(self):
        # Each argument on its own line, so the headline can be told apart.
        return self.logged("arg|")

    def setUp(self):
        super().setUp()
        self.stub("omarchy-notification-send", 'for a; do printf "arg|%s\\n" "$a" >> "$LOG"; done')

    def test_a_name_starting_with_a_dash_is_never_an_option(self):
        for name in ("-t", "--app-name=Omarchy", "-p", "--exec"):
            with self.subTest(name=name):
                self.log.unlink(missing_ok=True)
                self.arrive(name)
                self.assertEqual(self.argv()[:3], ["arg|-t", "arg|8000", f"arg|./{name}"])

    def test_other_names_are_shown_unchanged(self):
        for name in ("notes.txt", "a -b.txt", "x--y.pdf"):
            with self.subTest(name=name):
                self.log.unlink(missing_ok=True)
                self.arrive(name)
                self.assertEqual(self.argv()[2], f"arg|{name}")


class DecodeLockTests(NotificationFixture):
    """A burst of HEIC photos from a nearby sender must not decode all at
    once: every decode takes $XDG_RUNTIME_DIR/omdrop/decode.lock, the lock
    omdrop-core takes too, so the two stacks serialize with each other."""

    def test_a_decode_waits_for_the_lock_and_runs_once_it_is_free(self):
        lock_path = self.runtime / "omdrop" / "decode.lock"
        lock_path.parent.mkdir(mode=0o700)
        with open(lock_path, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            (self.root / "IMG_1.heic").write_bytes(b"photo")
            handling = subprocess.Popen([OMDROP, "handle", str(self.root / "IMG_1.heic")],
                                        env=self.env, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.PIPE, text=True)
            time.sleep(1)
            self.assertEqual(self.logged("heif-convert|"), [], "decoded while another held the lock")
            self.assertIsNone(handling.poll())
        _, err = handling.communicate(timeout=30)
        self.assertEqual(handling.returncode, 0, err)
        # The clipboard's JPEG and the preview: two decodes, one at a time.
        self.assertEqual(len(self.logged("heif-convert|")), 2)
        self.assertIsNotNone(self.notified_image())

    def test_decodes_never_overlap(self):
        # Each decode logs its start and end around a pause; with the lock,
        # no start comes between another decode's start and end.
        self.stub("heif-convert",
                  'printf "start\\n" >> "$LOG"; sleep 0.2; for a; do d=$a; done\n'
                  'printf jpeg > "$d"; printf "end\\n" >> "$LOG"')
        photos = []
        for n in range(3):
            photo = self.root / f"IMG_{n}.heic"
            photo.write_bytes(b"photo")
            photos.append(photo)
        handlers = [subprocess.Popen([OMDROP, "handle", str(p)], env=self.env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    for p in photos]
        for handler in handlers:
            self.assertEqual(handler.wait(timeout=60), 0)
        events = self.logged("start") + self.logged("end")
        self.assertEqual(len(events), 12)
        order = [line for line in self.log.read_text().splitlines() if line in ("start", "end")]
        self.assertEqual(order, ["start", "end"] * 6, order)

    def test_the_lock_is_private_to_the_user(self):
        self.arrive("IMG_1.heic")
        lock_path = self.runtime / "omdrop" / "decode.lock"
        self.assertEqual(lock_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(lock_path.parent.stat().st_mode & 0o777, 0o700)


if __name__ == "__main__":
    unittest.main()
