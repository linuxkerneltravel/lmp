import * as vscode from "vscode";
import * as fs from "fs";
import { port } from "./server";

export class GrafanaEditorProvider implements vscode.CustomTextEditorProvider {
  static webviewContent = "";
  static webviewErrorContent = "";

  static readonly viewType = "grafana.dashboard";

  public static register(context: vscode.ExtensionContext): vscode.Disposable {
    const provider = new GrafanaEditorProvider(context);
    const providerRegistration = vscode.window.registerCustomEditorProvider(
      GrafanaEditorProvider.viewType,
      provider,
      {
        webviewOptions: {
          retainContextWhenHidden: true,
        },
      },
    );
    this.webviewContent = fs.readFileSync(
      context.asAbsolutePath("public/webview.html"),
      "utf-8",
    );
    this.webviewContent = this.webviewContent.replaceAll("${editor}", "VSCode");

    return providerRegistration;
  }

  constructor(private readonly context: vscode.ExtensionContext) {}

  /**
   * Called when our custom editor is opened.
   */
  public async resolveCustomTextEditor(
    document: vscode.TextDocument,
    webviewPanel: vscode.WebviewPanel,
    _token: vscode.CancellationToken,
  ) {
    webviewPanel.webview.options = {
      enableScripts: true,
    };

    webviewPanel.webview.html = this.getHtmlForWebview(document);
  }

  private getTheme(): string {

    const settings = vscode.workspace.getConfiguration("grafana-vscode");
    const theme = settings.get<string>("theme");
    if (theme === "dark" || theme === "light") {
      return `theme=${theme}&`;
    }
    if (theme === "fixed") {
      return "";
    }

    const kind = vscode.window.activeColorTheme.kind;
    if (kind === vscode.ColorThemeKind.Light || kind === vscode.ColorThemeKind.HighContrastLight) {
      return "theme=light&";
    } else {
      return "theme=dark&";
    }
  }

  /**
   * Get the static html used for the editor webviews.
   */
  private getHtmlForWebview(document: vscode.TextDocument): string {
    const dash = JSON.parse(document.getText());
    const uid: string = dash.uid;
    const theme = this.getTheme();

    let view = GrafanaEditorProvider.webviewContent.replaceAll(
      "${filename}",
      document.uri.fsPath,
    );
    view = view.replaceAll("${port}", port.toString());
    view = view.replaceAll("${uid}", uid);
    view = view.replaceAll("${theme}", theme);
    return view;
  }
}
