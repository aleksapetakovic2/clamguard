"""The query editor: highlighting, a gutter, completion and a live error.

A query box that is only a text area makes people type ``Logs | wher`` and
stare at "syntax error". This one does the four things that stop that
happening:

* **Highlighting** that distinguishes a column from a function from a string,
  driven by the same catalogue the engine uses — so a colour is evidence that
  a name is real, not decoration.
* **A live check** on a short pause after typing. The parser and name
  resolver run with no connection and read no data, so it costs microseconds,
  and the offending token gets a wavy underline with the message on hover.
* **Completion** that knows where the cursor is: operators after a ``|``,
  columns inside a ``where``, aggregates inside a ``summarize``.
* **Ctrl+Enter to run**, because that is what every query tool in the world
  uses and muscle memory is not negotiable.

The widget paints nothing that a stylesheet could do instead, but the gutter
and the highlighter need real colours, so both take :meth:`apply_palette`.
"""

from __future__ import annotations

from PySide6.QtCore import QRect, QSize, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QFont,
    QKeyEvent,
    QPainter,
    QSyntaxHighlighter,
    QTextCharFormat,
    QTextCursor,
    QTextDocument,
    QTextFormat,
)
from PySide6.QtWidgets import (
    QCompleter,
    QListView,
    QPlainTextEdit,
    QTextEdit,
    QWidget,
)

from ...core.hunt.kql import complete as completion
from ...core.hunt.kql.errors import KqlError
from ..theme import MONO_FONT_STACK, Palette, pick_font

#: How long after the last keystroke the query is checked, in milliseconds.
CHECK_DELAY = 350

#: Width of the line-number gutter's padding, either side of the digits.
GUTTER_PADDING = 10


class KqlHighlighter(QSyntaxHighlighter):
    """Colours a KQL document using the engine's own name lists.

    Rules are applied in order and later ones win, which is how ``count`` gets
    the function colour rather than the keyword colour even though it is in
    both lists.
    """

    def __init__(self, document: QTextDocument) -> None:
        super().__init__(document)
        self._keywords = set(completion.keywords())
        self._functions = set(completion.function_names())
        self._columns = {name.lower() for name in completion.column_names()}
        self._tables = {name.lower() for name in completion.table_names()}
        self._formats: dict[str, QTextCharFormat] = {}
        self.apply_palette(None, "#3b82f6")

    def apply_palette(self, palette: Palette | None, accent: str) -> None:
        """Rebuild the colour table. Called whenever the theme changes."""
        dark = palette.is_dark if palette else True
        text = palette.text if palette else "#e8ecf4"
        faint = palette.text_faint if palette else "#6b7688"

        def made(colour: str, *, bold: bool = False, italic: bool = False,
                 underline: bool = False) -> QTextCharFormat:
            style = QTextCharFormat()
            style.setForeground(QColor(colour))
            if bold:
                style.setFontWeight(QFont.Weight.DemiBold)
            if italic:
                style.setFontItalic(True)
            if underline:
                style.setUnderlineStyle(
                    QTextCharFormat.UnderlineStyle.SpellCheckUnderline)
            return style

        self._formats = {
            "keyword": made(accent, bold=True),
            "operator": made("#c792ea" if dark else "#7c3aed"),
            "function": made("#82aaff" if dark else "#1d4ed8"),
            "aggregate": made("#82aaff" if dark else "#1d4ed8", bold=True),
            "table": made("#f78c6c" if dark else "#b45309", bold=True),
            "column": made(text),
            "string": made("#7ee787" if dark else "#15803d"),
            "number": made("#ffcb6b" if dark else "#a16207"),
            "timespan": made("#ffcb6b" if dark else "#a16207", bold=True),
            "comment": made(faint, italic=True),
            "pipe": made(accent, bold=True),
        }
        self.rehighlight()

    def highlightBlock(self, text: str) -> None:  # noqa: N802 - Qt naming
        length = len(text)
        index = 0
        while index < length:
            character = text[index]

            if character in " \t":
                index += 1
                continue

            if character == "/" and text.startswith("//", index):
                self.setFormat(index, length - index, self._formats["comment"])
                return

            if character in "\"'" or (character == "@" and index + 1 < length
                                      and text[index + 1] in "\"'"):
                index = self._string(text, index, length)
                continue

            if character == "|":
                self.setFormat(index, 1, self._formats["pipe"])
                index += 1
                continue

            if character.isdigit():
                index = self._number(text, index, length)
                continue

            if character.isalpha() or character in "_$":
                index = self._word(text, index, length)
                continue

            if character in "=!<>~+-*/%":
                start = index
                while index < length and text[index] in "=!<>~+-*/%":
                    index += 1
                self.setFormat(start, index - start, self._formats["operator"])
                continue

            index += 1

    def _string(self, text: str, index: int, length: int) -> int:
        start = index
        if text[index] == "@":
            index += 1
        quote = text[index]
        index += 1
        while index < length:
            if text[index] == "\\" and text[start] != "@":
                index += 2
                continue
            if text[index] == quote:
                index += 1
                break
            index += 1
        self.setFormat(start, index - start, self._formats["string"])
        return index

    def _number(self, text: str, index: int, length: int) -> int:
        start = index
        while index < length and (text[index].isdigit() or text[index] in ".xXeE"
                                  or (text[index] in "abcdefABCDEF"
                                      and text[start:start + 2].lower() == "0x")):
            index += 1
        unit = index
        while unit < length and text[unit].isalpha():
            unit += 1
        style = "timespan" if unit > index else "number"
        self.setFormat(start, unit - start, self._formats[style])
        return unit

    def _word(self, text: str, index: int, length: int) -> int:
        start = index
        if text[index] == "$":
            index += 1
        while index < length and (text[index].isalnum() or text[index] == "_"):
            index += 1
        word = text[start:index]
        lowered = word.lower()

        # `project-away` and friends are one word with a hyphen in the middle.
        if index < length and text[index] == "-" and index + 1 < length \
                and text[index + 1].isalpha():
            ahead = index + 1
            while ahead < length and (text[ahead].isalnum() or text[ahead] == "_"):
                ahead += 1
            if f"{lowered}-{text[index + 1:ahead].lower()}" in self._keywords:
                self.setFormat(start, ahead - start, self._formats["keyword"])
                return ahead

        if lowered in self._tables:
            style = "table"
        elif word in self._functions or lowered in self._functions:
            style = "aggregate" if _is_aggregate(lowered) else "function"
        elif lowered in self._keywords:
            style = "keyword"
        elif lowered in self._columns:
            style = "column"
        else:
            return index
        self.setFormat(start, index - start, self._formats[style])
        return index


def _is_aggregate(name: str) -> bool:
    from ...core.hunt.kql.functions import AGGREGATES

    return name in AGGREGATES


class _Gutter(QWidget):
    """The line-number strip. A child of the editor, painted by it."""

    def __init__(self, editor: "KqlEditor") -> None:
        super().__init__(editor)
        self._editor = editor

    def sizeHint(self) -> QSize:  # noqa: N802 - Qt naming
        return QSize(self._editor.gutter_width(), 0)

    def paintEvent(self, event) -> None:  # noqa: N802 - Qt naming
        self._editor.paint_gutter(event)


class KqlEditor(QPlainTextEdit):
    """A code editor for one KQL query."""

    #: The user asked to run the query (Ctrl+Enter, or Shift+Enter).
    run_requested = Signal()
    #: The live check finished. The argument is a KqlError or None.
    checked = Signal(object)
    #: The cursor moved onto a different token; carries its documentation.
    hint_changed = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("kqlEditor")
        self.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.setTabChangesFocus(False)
        self.setPlaceholderText("Logs\n| where Level == \"error\"\n| take 100")

        font = QFont(pick_font(MONO_FONT_STACK, "monospace"))
        font.setPointSizeF(10.5)
        font.setStyleHint(QFont.StyleHint.Monospace)
        self.setFont(font)
        self.setTabStopDistance(self.fontMetrics().horizontalAdvance(" ") * 4)

        self.highlighter = KqlHighlighter(self.document())
        self._gutter = _Gutter(self)
        self._error: KqlError | None = None
        self._line_colour = QColor(0, 0, 0, 0)
        self._gutter_background = QColor(0, 0, 0, 0)
        self._gutter_text = QColor(120, 120, 120)
        self._gutter_current = QColor(200, 200, 200)
        self._extra_columns: tuple[str, ...] = ()
        self._saved_names: tuple[str, ...] = ()

        self._completer = QCompleter(self)
        self._completer.setWidget(self)
        self._completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        self._completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self._completer.activated.connect(self._insert_completion)
        popup = QListView()
        popup.setObjectName("completerPopup")
        popup.setUniformItemSizes(True)
        self._completer.setPopup(popup)
        self._completions: list[completion.Completion] = []

        self._check_timer = QTimer(self)
        self._check_timer.setSingleShot(True)
        self._check_timer.setInterval(CHECK_DELAY)
        self._check_timer.timeout.connect(self._run_check)

        self.blockCountChanged.connect(lambda _count: self._resize_gutter())
        self.updateRequest.connect(self._scroll_gutter)
        self.cursorPositionChanged.connect(self._on_cursor_moved)
        self.textChanged.connect(self._on_text_changed)
        self._resize_gutter()

    # -- theme ------------------------------------------------------------

    def apply_palette(self, palette: Palette, accent: str) -> None:
        self.highlighter.apply_palette(palette, accent)
        self._line_colour = QColor(palette.surface_2)
        self._gutter_background = QColor(palette.surface_2)
        self._gutter_text = QColor(palette.text_faint)
        self._gutter_current = QColor(accent)
        self._highlight_current_line()
        self._gutter.update()

    # -- the gutter -------------------------------------------------------

    def gutter_width(self) -> int:
        digits = max(2, len(str(max(1, self.blockCount()))))
        return GUTTER_PADDING * 2 + self.fontMetrics().horizontalAdvance("9") * digits

    def _resize_gutter(self) -> None:
        self.setViewportMargins(self.gutter_width(), 0, 0, 0)

    def _scroll_gutter(self, rect: QRect, delta: int) -> None:
        if delta:
            self._gutter.scroll(0, delta)
        else:
            self._gutter.update(0, rect.y(), self._gutter.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self._resize_gutter()

    def resizeEvent(self, event) -> None:  # noqa: N802 - Qt naming
        super().resizeEvent(event)
        box = self.contentsRect()
        self._gutter.setGeometry(QRect(box.left(), box.top(),
                                       self.gutter_width(), box.height()))

    def paint_gutter(self, event) -> None:
        painter = QPainter(self._gutter)
        painter.fillRect(event.rect(), self._gutter_background)

        block = self.firstVisibleBlock()
        number = block.blockNumber()
        offset = self.contentOffset()
        top = self.blockBoundingGeometry(block).translated(offset).top()
        bottom = top + self.blockBoundingRect(block).height()
        current = self.textCursor().blockNumber()
        width = self._gutter.width() - GUTTER_PADDING

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                painter.setPen(self._gutter_current if number == current
                               else self._gutter_text)
                painter.drawText(0, int(top), width,
                                 self.fontMetrics().height(),
                                 int(Qt.AlignmentFlag.AlignRight
                                     | Qt.AlignmentFlag.AlignVCenter),
                                 str(number + 1))
            block = block.next()
            top = bottom
            bottom = top + self.blockBoundingRect(block).height()
            number += 1
        painter.end()

    # -- checking ---------------------------------------------------------

    def _on_text_changed(self) -> None:
        self._check_timer.start()

    def _run_check(self) -> None:
        from ...core.hunt.kql.engine import check

        text = self.toPlainText()
        self._error = check(text) if text.strip() else None
        self._highlight_current_line()
        self.checked.emit(self._error)

    @property
    def error(self) -> KqlError | None:
        return self._error

    def set_error(self, error: KqlError | None) -> None:
        """Show an error the engine reported, rather than one we found."""
        self._error = error
        self._highlight_current_line()

    def _highlight_current_line(self) -> None:
        selections: list[QTextEdit.ExtraSelection] = []

        line = QTextEdit.ExtraSelection()
        line.format.setBackground(self._line_colour)
        line.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
        line.cursor = self.textCursor()
        line.cursor.clearSelection()
        selections.append(line)

        if self._error is not None:
            squiggle = QTextEdit.ExtraSelection()
            squiggle.format.setUnderlineStyle(
                QTextCharFormat.UnderlineStyle.WaveUnderline)
            squiggle.format.setUnderlineColor(QColor("#ff5c5c"))
            squiggle.format.setToolTip(self._error.full_message())
            cursor = self.textCursor()
            cursor.setPosition(min(self._error.position, len(self.toPlainText())))
            cursor.setPosition(
                min(self._error.position + self._error.length,
                    len(self.toPlainText())),
                QTextCursor.MoveMode.KeepAnchor)
            squiggle.cursor = cursor
            selections.append(squiggle)

        self.setExtraSelections(selections)

    def _on_cursor_moved(self) -> None:
        self._highlight_current_line()
        text = self.toPlainText()
        position = self.textCursor().position()
        word, _start = completion.word_at(text, position)
        hint = completion.documentation_for(word) if word else ""
        self.hint_changed.emit(hint or completion.signature_for(text, position))

    # -- completion -------------------------------------------------------

    def set_result_columns(self, names: tuple[str, ...]) -> None:
        """Offer the columns a previous run produced, as well as the table's."""
        self._extra_columns = names

    def set_saved_names(self, names: tuple[str, ...]) -> None:
        self._saved_names = names

    def _show_completions(self, *, forced: bool = False) -> None:
        text = self.toPlainText()
        position = self.textCursor().position()
        prefix, start = completion.word_at(text, position)
        if not forced and len(prefix) < 2:
            self._completer.popup().hide()
            return

        items = completion.completions(text, position,
                                       extra_columns=self._extra_columns,
                                       saved_names=self._saved_names)
        if not items:
            self._completer.popup().hide()
            return

        self._completions = items
        from PySide6.QtCore import QStringListModel

        labels = [f"{item.label}   {item.detail}".rstrip() for item in items]
        self._completer.setModel(QStringListModel(labels, self._completer))
        self._completer.setCompletionPrefix("")

        rect = self.cursorRect()
        popup = self._completer.popup()
        rect.setWidth(max(360, popup.sizeHintForColumn(0)
                          + popup.verticalScrollBar().sizeHint().width() + 24))
        rect.setLeft(rect.left() - self.fontMetrics().horizontalAdvance(prefix))
        self._completer.complete(rect)
        popup.setCurrentIndex(self._completer.completionModel().index(0, 0))

    def _insert_completion(self, text: str) -> None:
        index = self._completer.popup().currentIndex().row()
        if 0 <= index < len(self._completions):
            insertion = self._completions[index].text
        else:
            insertion = text.split("   ")[0]

        cursor = self.textCursor()
        body = self.toPlainText()
        _prefix, start = completion.word_at(body, cursor.position())
        cursor.setPosition(start)
        cursor.setPosition(self.textCursor().position(),
                           QTextCursor.MoveMode.KeepAnchor)
        cursor.insertText(insertion)
        self.setTextCursor(cursor)

    # -- keys -------------------------------------------------------------

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802 - Qt naming
        popup = self._completer.popup()
        if popup.isVisible() and event.key() in (
                Qt.Key.Key_Enter, Qt.Key.Key_Return, Qt.Key.Key_Tab,
                Qt.Key.Key_Escape, Qt.Key.Key_Up, Qt.Key.Key_Down,
                Qt.Key.Key_PageUp, Qt.Key.Key_PageDown):
            if event.key() in (Qt.Key.Key_Enter, Qt.Key.Key_Return, Qt.Key.Key_Tab):
                self._insert_completion(popup.currentIndex().data() or "")
                popup.hide()
                return
            if event.key() == Qt.Key.Key_Escape:
                popup.hide()
                return
            event.ignore()
            return

        modifiers = event.modifiers()
        if event.key() in (Qt.Key.Key_Enter, Qt.Key.Key_Return):
            if modifiers & (Qt.KeyboardModifier.ControlModifier
                            | Qt.KeyboardModifier.ShiftModifier):
                self.run_requested.emit()
                return
            self._newline_with_indent()
            return

        if event.key() == Qt.Key.Key_Space and \
                modifiers & Qt.KeyboardModifier.ControlModifier:
            self._show_completions(forced=True)
            return

        if event.key() == Qt.Key.Key_Tab and not modifiers:
            self.insertPlainText("    ")
            return

        super().keyPressEvent(event)

        if event.text() and (event.text().isalnum() or event.text() in "_.|"):
            self._show_completions()
        elif popup.isVisible():
            popup.hide()

    def _newline_with_indent(self) -> None:
        """Keep the pipe alignment when Enter is pressed inside a pipeline.

        A KQL query is read down the left edge, so a new line in the middle of
        one should land under the pipes rather than at column zero.
        """
        cursor = self.textCursor()
        line = cursor.block().text()
        indent = line[: len(line) - len(line.lstrip())]
        cursor.insertText("\n" + indent)
        self.setTextCursor(cursor)

    # -- convenience ------------------------------------------------------

    def set_query(self, text: str, *, run: bool = False) -> None:
        self.setPlainText(text)
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.setTextCursor(cursor)
        if run:
            self.run_requested.emit()

    def insert_at_cursor(self, text: str) -> None:
        """Put a name or a snippet where the cursor is."""
        cursor = self.textCursor()
        if cursor.position() and self.toPlainText()[cursor.position() - 1] not in " \n|(,":
            text = " " + text
        cursor.insertText(text)
        self.setTextCursor(cursor)
        self.setFocus()

    def append_stage(self, text: str) -> None:
        """Add ``| where …`` on a new line at the end of the query."""
        body = self.toPlainText().rstrip()
        self.setPlainText(f"{body}\n| {text}" if body else text)
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.setTextCursor(cursor)

    def current_line_text(self) -> str:
        return self.textCursor().block().text()
