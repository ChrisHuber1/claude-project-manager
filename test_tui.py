"""Minimal test: does Textual handle mouse/keyboard on this terminal?"""
from textual.app import App
from textual.screen import Screen
from textual.containers import Vertical, Horizontal
from textual.widgets import Button, DataTable, Header, Footer, Static, Label


class TestScreen(Screen):
    BINDINGS = [("escape", "pop_screen", "Back")]

    def compose(self):
        yield Header()
        with Vertical():
            yield Label("TEST SCREEN -- click a button or use arrow keys on the table")
            yield DataTable(id="tbl")
            with Horizontal():
                yield Button("Button A", id="btn-a", variant="success")
                yield Button("Button B", id="btn-b", variant="error")
                yield Button("Back", id="btn-back", variant="default")
        yield Footer()

    def on_mount(self):
        tbl = self.query_one("#tbl", DataTable)
        tbl.add_columns("Name", "Value")
        tbl.cursor_type = "row"
        for i in range(8):
            tbl.add_row(f"Project {i}", f"val-{i}")
        tbl.focus()

    def on_button_pressed(self, event):
        self.app.query_one("#result", Static).update(
            f"Button pressed: {event.button.id}"
        )

    def on_data_table_row_selected(self, event):
        tbl = self.query_one("#tbl", DataTable)
        row = tbl.get_row(event.row_key)
        self.app.query_one("#result", Static).update(
            f"Row selected: {row}"
        )


class TestApp(App):
    BINDINGS = [("t", "test", "Open Test"), ("q", "quit", "Quit")]

    def compose(self):
        yield Header()
        with Vertical():
            yield Label("Press 't' to open the test screen")
            yield Static("No result yet", id="result")
        yield Footer()

    def action_test(self):
        self.push_screen(TestScreen())


if __name__ == "__main__":
    TestApp().run()
