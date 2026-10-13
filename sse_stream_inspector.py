"""SSE and streaming-response inspector for Burp's legacy Jython Extender API."""

import re
import time

from burp import (
    IBurpExtender,
    ITab,
    IContextMenuFactory,
    IMessageEditorTabFactory,
    IMessageEditorTab,
)
from java.awt import BorderLayout, FlowLayout
from java.awt.event import ActionListener
from java.util import ArrayList
from javax.swing import (
    JButton,
    JLabel,
    JMenuItem,
    JPanel,
    JScrollPane,
    JSplitPane,
    SwingWorker,
    JTable,
    JTextArea,
)
from javax.swing.table import DefaultTableModel


_SENSITIVE_PATTERNS = [
    ("credential field", re.compile(r"(?i)(password|passwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|otp|session[_-]?id)\s*[\"']?\s*[:=]")),
    ("bearer token", re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/-]+=*")),
    ("JWT", re.compile(r"\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b")),
    ("email address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("possible payment-card number", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
]


def _scan_sensitive(text):
    matches = []
    for label, pattern in _SENSITIVE_PATTERNS:
        if pattern.search(text):
            matches.append(label)
    return matches


def _parse_sse(body):
    events = []
    current = {"event": "message", "data": []}
    last_event_id = ""
    retry_value = ""

    def dispatch():
        if current["data"]:
            events.append(
                {
                    "event": current["event"] or "message",
                    "id": last_event_id,
                    "retry": retry_value,
                    "data": "\n".join(current["data"]),
                }
            )
        current["event"] = "message"
        current["data"] = []

    for line in body.splitlines():
        if line == "":
            dispatch()
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "data":
            current["data"].append(value)
        elif field == "event":
            current["event"] = value
        elif field == "id" and "\x00" not in value:
            last_event_id = value
        elif field == "retry" and value.isdigit():
            retry_value = value
    dispatch()
    return events


def _decode_chunked(body):
    chunks = []
    offset = 0
    try:
        while True:
            line_end = body.find("\r\n", offset)
            if line_end < 0:
                return body
            size_text = body[offset:line_end].split(";", 1)[0].strip()
            size = int(size_text, 16)
            offset = line_end + 2
            if size == 0:
                return "".join(chunks)
            chunk_end = offset + size
            if chunk_end + 2 > len(body) or body[chunk_end:chunk_end + 2] != "\r\n":
                return body
            chunks.append(body[offset:chunk_end])
            offset = chunk_end + 2
    except Exception:
        return body


def _response_events(helpers, response):
    if response is None:
        return [], "No response available."
    response_info = helpers.analyzeResponse(response)
    headers = response_info.getHeaders()
    content_type = ""
    transfer_encoding = ""
    for header in headers:
        lower_header = str(header).lower()
        if lower_header.startswith("content-type:"):
            content_type = lower_header
        elif lower_header.startswith("transfer-encoding:"):
            transfer_encoding = lower_header
    body = helpers.bytesToString(response[response_info.getBodyOffset():])
    if "chunked" in transfer_encoding:
        body = _decode_chunked(body)
    events = _parse_sse(body)
    if events:
        message = "%d event(s); response status %s; %s" % (
            len(events),
            response_info.getStatusCode(),
            content_type or "SSE content type not declared",
        )
    else:
        message = "No SSE data events found; response status %s." % response_info.getStatusCode()
    return events, message


class _Action(ActionListener):
    def __init__(self, callback):
        self.callback = callback

    def actionPerformed(self, event):
        self.callback()


class _ReadOnlyModel(DefaultTableModel):
    def isCellEditable(self, row, column):
        return False


class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.current_service = None
        self.replaying = False
        callbacks.setExtensionName("SSE Stream Inspector")
        callbacks.registerContextMenuFactory(self)
        callbacks.registerMessageEditorTabFactory(self)
        self._build_ui()
        callbacks.addSuiteTab(self)
        callbacks.printOutput("SSE Stream Inspector loaded")

    def getTabCaption(self):
        return "SSE Inspector"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
        item = JMenuItem("Load request in SSE Inspector")
        item.addActionListener(_Action(lambda: self._load_message(messages[0])))
        menu_items = ArrayList()
        menu_items.add(item)
        return menu_items

    def createNewInstance(self, controller, editable):
        return _SseMessageTab(self, controller, editable)

    def _build_ui(self):
        self.panel = JPanel(BorderLayout(6, 6))
        request_panel = JPanel(BorderLayout())
        request_panel.add(JLabel("Editable HTTP request"), BorderLayout.NORTH)
        self.request_area = JTextArea()
        self.request_area.setLineWrap(False)
        request_panel.add(JScrollPane(self.request_area), BorderLayout.CENTER)

        event_panel = JPanel(BorderLayout())
        self.event_model = _ReadOnlyModel(
            ["#", "Event", "ID", "Retry", "Timing", "Sensitive data", "Data"], 0
        )
        self.event_table = JTable(self.event_model)
        self.event_table.setAutoCreateRowSorter(True)
        event_panel.add(JScrollPane(self.event_table), BorderLayout.CENTER)
        self.detail_area = JTextArea()
        self.detail_area.setEditable(False)
        self.detail_area.setLineWrap(True)
        self.detail_area.setRows(4)
        event_panel.add(JScrollPane(self.detail_area), BorderLayout.SOUTH)

        split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, request_panel, event_panel)
        split.setResizeWeight(0.42)
        self.panel.add(split, BorderLayout.CENTER)

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        self.replay_button = JButton("Replay and inspect")
        self.clear_button = JButton("Clear")
        self.replay_button.addActionListener(_Action(self._replay))
        self.clear_button.addActionListener(_Action(self._clear))
        controls.add(self.replay_button)
        controls.add(self.clear_button)
        self.status_label = JLabel(
            "Select a Burp request from Proxy history or Repeater to begin."
        )
        controls.add(self.status_label)
        self.panel.add(controls, BorderLayout.SOUTH)

    def _load_message(self, message_info):
        request = message_info.getRequest()
        service = message_info.getHttpService()
        if request is None or service is None:
            return
        self.current_service = service
        self.request_area.setText(self.helpers.bytesToString(request))
        self.request_area.setCaretPosition(0)
        response = message_info.getResponse()
        if response is not None:
            events, summary = _response_events(self.helpers, response)
            self._show_events(events)
            self.status_label.setText(summary)
            self.detail_area.setText(
                "Burp's legacy Python API provides completed response bytes, not per-event "
                "arrival timestamps. Timing is therefore shown as unavailable."
            )
        else:
            self._show_events([])
            self.status_label.setText("Request loaded. Edit it if needed, then replay.")
            self.detail_area.setText("")

    def _replay(self):
        if self.replaying:
            return
        if self.current_service is None:
            self.status_label.setText("Load a request from Proxy history or Repeater first.")
            return
        request_text = self.request_area.getText()
        if not request_text.strip():
            self.status_label.setText("The request is empty.")
            return
        try:
            request = self.helpers.stringToBytes(request_text)
        except Exception as error:
            self.status_label.setText("Could not encode request: " + str(error))
            return

        self.replaying = True
        self.replay_button.setEnabled(False)
        self.status_label.setText(
            "Replaying via Burp. A long-lived stream may not finish until the server closes it..."
        )
        extension = self
        service = self.current_service

        class ReplayWorker(SwingWorker):
            def doInBackground(worker_self):
                started = time.time()
                exchange = extension.callbacks.makeHttpRequest(service, request)
                elapsed_ms = int((time.time() - started) * 1000)
                response = exchange.getResponse() if exchange is not None else None
                return response, elapsed_ms

            def done(worker_self):
                extension.replaying = False
                extension.replay_button.setEnabled(True)
                try:
                    response, elapsed_ms = worker_self.get()
                    events, summary = _response_events(extension.helpers, response)
                    extension._show_events(events)
                    extension.status_label.setText(
                        "%s Total request duration: %d ms." % (summary, elapsed_ms)
                    )
                    extension.detail_area.setText(
                        "Total request duration is measured. Individual SSE event arrival "
                        "times are unavailable because Burp's legacy Python API buffers the "
                        "response before returning it."
                    )
                except Exception as error:
                    extension.status_label.setText("Replay failed: " + str(error))

        ReplayWorker().execute()

    def _show_events(self, events):
        self.event_model.setRowCount(0)
        for index, event in enumerate(events, 1):
            flags = _scan_sensitive(event["data"])
            self.event_model.addRow(
                [
                    str(index),
                    event["event"],
                    event["id"],
                    event["retry"],
                    "Unavailable",
                    ", ".join(flags) if flags else "None detected",
                    event["data"],
                ]
            )

    def _clear(self):
        if self.replaying:
            return
        self.current_service = None
        self.request_area.setText("")
        self.event_model.setRowCount(0)
        self.detail_area.setText("")
        self.status_label.setText("Cleared.")


class _SseMessageTab(IMessageEditorTab):
    def __init__(self, extension, controller, editable):
        self.extension = extension
        self.helpers = extension.helpers
        self.message = None
        self.panel = JPanel(BorderLayout())
        self.model = _ReadOnlyModel(
            ["#", "Event", "ID", "Retry", "Timing", "Sensitive data", "Data"], 0
        )
        self.table = JTable(self.model)
        self.table.setAutoCreateRowSorter(True)
        self.panel.add(JScrollPane(self.table), BorderLayout.CENTER)
        self.status = JLabel("SSE event view; per-event arrival timing is unavailable in the legacy API.")
        self.panel.add(self.status, BorderLayout.SOUTH)

    def getTabCaption(self):
        return "SSE Events"

    def getUiComponent(self):
        return self.panel

    def isEnabled(self, content, isRequest):
        if isRequest or content is None:
            return False
        try:
            response_info = self.helpers.analyzeResponse(content)
            content_type = " ".join(response_info.getHeaders()).lower()
            if "text/event-stream" in content_type:
                return True
            body = self.helpers.bytesToString(content[response_info.getBodyOffset():])
            return bool(_parse_sse(body))
        except Exception:
            return False

    def setMessage(self, content, isRequest):
        self.message = content
        self.model.setRowCount(0)
        if content is None or isRequest:
            self.status.setText("No SSE response selected.")
            return
        events, summary = _response_events(self.helpers, content)
        for index, event in enumerate(events, 1):
            flags = _scan_sensitive(event["data"])
            self.model.addRow(
                [
                    str(index),
                    event["event"],
                    event["id"],
                    event["retry"],
                    "Unavailable",
                    ", ".join(flags) if flags else "None detected",
                    event["data"],
                ]
            )
        self.status.setText(summary + ". Event arrival times are not exposed by this API.")

    def getMessage(self):
        return self.message

    def isModified(self):
        return False

    def getSelectedData(self):
        selected_row = self.table.getSelectedRow()
        if selected_row < 0:
            return None
        model_row = self.table.convertRowIndexToModel(selected_row)
        data = self.model.getValueAt(model_row, 6)
        return self.helpers.stringToBytes(str(data))