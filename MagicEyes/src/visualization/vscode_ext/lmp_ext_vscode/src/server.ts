import * as express from "express";
import { Server, createServer } from "http";
import { createProxyServer } from "http-proxy";
import * as fs from "fs";
import * as vscode from "vscode";
import * as cors from "cors";
import { detectRequestSource } from "./middleware";
import axios from "axios";
import * as path from "path";
import * as util from "./util";

export let port = 0;

let server: Server;

export const TOKEN_SECRET = "grafana-vscode.token";

export async function startServer(secrets: vscode.SecretStorage, extensionPath: string) {
  const settings = vscode.workspace.getConfiguration("grafana-vscode");
  const token = await secrets.get(TOKEN_SECRET);
  let URL = String(settings.get("URL"));
  if (URL.slice(-1) === "/") {
    URL = URL.slice(0, -1);
  }

  const corsOptions = {
    origin: `http://localhost:${port}`,
    optionsSuccessStatus: 200,
  };

  const app = express();
  app.use(detectRequestSource);
  server = createServer(app);

  const proxy = createProxyServer({
    target: URL,
    changeOrigin: !URL.includes("localhost"),
    ws: true,
    headers: {
      // eslint-disable-next-line @typescript-eslint/naming-convention
      Authorization: `Bearer ${token}`,
      // eslint-disable-next-line @typescript-eslint/naming-convention
      'User-Agent': util.getUserAgent(),
    },
  });

  server.on("upgrade", function (req, socket, head) {
    proxy.ws(req, socket, head, {});
  });

  const sendErrorPage = (res: express.Response, message: string) => {
    const errorFile = path.join(extensionPath, "public/error.html");
    let content = fs.readFileSync(errorFile, "utf-8");
    content = content.replaceAll("${error}", message);
    res.write(content);
  };

  /*
   * Note, this method avoids using `proxy.web`, implementing its own proxy
   * event using Axios. This is because Grafana returns `X-Frame-Options: deny`
   * which breaks our ability to place Grafana inside an iframe. `http-proxy`
   * will not remove that header once it is added. Therefore we need a different
   * form of proxy.
   *
   * This security protection does not apply to this situation - given we own
   * both the connection to the backend as well as the webview. Therefore
   * it is reasonable remove this header in this context.
   * 
   * This method also doubles as connection verification. If an issue is
   * encountered connecting to Grafana, rather than reporting an HTTP error,
   * it returns an alternate HTML page to the user explaining the error, and
   * offering a "refresh" option.
   */
  app.get("/d/:uid/:slug", async function (req, res) {
    try {
      const resp = await axios.get(URL + req.url, {
        maxRedirects: 5,
        headers: {
          // eslint-disable-next-line @typescript-eslint/naming-convention
          Authorization: `Bearer ${token}`,
          // eslint-disable-next-line @typescript-eslint/naming-convention
          'User-Agent': util.getUserAgent(),
        },
      });
      res.write(resp.data);
    } catch (e) {
      let msg = "";
      if (URL === "") {
        msg += "<p><b>Error:</b> URL is not defined</p>";
      }
      if (token === "") {
        msg += "<p><b>Warning:</b> No service account token specified.</p>";
      }
      if (axios.isAxiosError(e)) {
        if (e.response?.status === 302) {
          sendErrorPage(res, msg+ "<p>Authentication error</p>");
        } else {
          sendErrorPage(res, msg + `<p>${e.message}</p>`);
        }
      } else if (e instanceof Error) {
        sendErrorPage(res, msg + `<p>${e.message}</p>`);
      } else {
        sendErrorPage(res, msg + "<p>" + String(e) + "</p>");
      }
    }
  });

  app.get(
    "/api/dashboards/uid/:uid",
    express.json(),
    cors(corsOptions),
    (req, res) => {
      const refererParams = new URLSearchParams(req.headers.referer);
      const filename = refererParams.get("filename");
      if (filename === null) {
        console.log("Filename not specified in referer");
        res.sendStatus(500);
        return;
      }
      fs.readFile(filename, "utf-8", (err, data) => {
        if (err) {
          console.error("Error reading file:", err);
          res.sendStatus(500);
          return;
        }
        const dash: any = JSON.parse(data);
        const wrapper = {
          dashboard: dash,
          meta: {
            isStarred: false,
            folderId: 0,
            folderUid: "",
            url: `/d/${dash.uid}/slug`,
          },
        };

        res.send(wrapper);
      });
    },
  );

  app.post(
    "/api/dashboards/db/",
    express.json(),
    cors(corsOptions),
    (req, res) => {
      const refererParams = new URLSearchParams(req.headers.referer);
      const filename = refererParams.get("filename");
      if (!filename) {
        res.send(500);
        return;
      }
      const uid = req.headers.referer?.split("/")[4];
      const jsonData = JSON.stringify(req.body.dashboard, null, 2);

      fs.writeFile(filename, jsonData, "utf-8", (err) => {
        if (err) {
          console.error("Error writing file:", err);
          res.sendStatus(500);
        } else {
          res.send({
            id: 1,
            slug: "slug",
            status: "success",
            uid: uid,
            url: `/d/${uid}/slug`,
            version: 1,
          });
        }
      });
    },
  );

  app.get(
    "/api/access-control/user/actions",
    express.json(),
    cors(corsOptions),
    (req, res) => {
      res.send({
        /* eslint-disable-next-line @typescript-eslint/naming-convention */
        "dashboards:write": true,
      });
      return;
    },
  );

  const mustProxyGET = [
    "/public/*",
    "/api/datasources/proxy/*",
    "/api/datasources/*",
    "/api/plugins/*",
  ];
  for (const path of mustProxyGET) {
    app.get(path, function (req, res) {
      proxy.web(req, res, {});
    });
  }

  const mustProxyPOST = [
    "/api/ds/query",
    "/api/datasources/proxy/*",
  ];
  for (const path of mustProxyPOST) {
    app.post(path, function (req, res) {
      proxy.web(req, res, {});
    });
  }

  const blockJSONget: { [name: string]: any } = {
    /* eslint-disable @typescript-eslint/naming-convention */
    "/api/ma/events": [],
    "/api/live/publish": [],
    "/api/live/list": [],
    "/api/user/orgs": [],
    "/api/annotations": [],
    "/api/search": [],
    "/api/usage/*": [],
    "/api/prometheus/grafana/api/v1/rules": {
      status: "success",
      data: { groups: [] },
    },
    "/avatar/*": "",
    "/api/folders": [],
    /* eslint-enable @typescript-eslint/naming-convention */
  };
  for (const path in blockJSONget) {
    app.get(path, function (req, res) {
      res.send(blockJSONget[path]);
    });
  }

  const blockJSONpost: { [name: string]: any } = {
    /* eslint-disable @typescript-eslint/naming-convention */
    "/api/frontend-metrics": [],
    "/api/search-v2": [],
    "/api/live/publish": {},
    /* eslint-enable @typescript-eslint/naming-convention */
  };
  for (const path in blockJSONpost) {
    app.post(path, function (req, res) {
      res.send(blockJSONpost[path]);
    });
  }

  server.listen(port, () => {
    //@ts-expect-error
    port = server?.address()?.port;
    console.log("Server started");
  });
}

export function restartServer(secrets: vscode.SecretStorage, extensionPath: string) {
  console.log("Restarting server");
  stopServer();
  startServer(secrets, extensionPath);
}
export function stopServer() {
  if (server) {
    server.close();
  }
}
