import * as vscode from "vscode";
import axios from "axios";
import {v4 as uuidv4} from 'uuid';
import * as util from "./util";

const LAST_UPDATED_DATE = "lastUpdatedDate";
const INSTALLATION_DATE = "installDate";
const INSTALLATION_UUID = "installUUID";
const RECENT_VIEWS = "recentViews";

const URL = "https://stats.grafana.org/vscode-usage-report";

/*
 * Sends a single anonymous telemetry call once per day, allowing tracking of
 * usage - reports on first opening of a dashboard each day.
 */
export async function sendTelemetry(ctx: vscode.ExtensionContext) {

    const settings = vscode.workspace.getConfiguration("grafana-vscode");
    const enableTelemetry = settings.get<boolean>("telemetry");
    if (!enableTelemetry) {
        return;
    }
    const lastUpdatedDate = ctx.globalState.get<string | undefined>(LAST_UPDATED_DATE);
    const today = new Date();

    if (lastUpdatedDate === undefined) {
        const uuid = uuidv4();
        await sendEvent("first", uuid, today.toISOString(), 1);
        ctx.globalState.update(LAST_UPDATED_DATE, today);
        ctx.globalState.update(INSTALLATION_UUID, uuid);
        ctx.globalState.update(INSTALLATION_DATE, today);
        ctx.globalState.update(RECENT_VIEWS, 0);
    } else {
        let recentViews = ctx.globalState.get<number | undefined>(RECENT_VIEWS);
        recentViews = (recentViews === undefined) ? 1 : recentViews+1;

        if (differentDay(new Date(lastUpdatedDate), today)) {
            let uuid = ctx.globalState.get(INSTALLATION_UUID);
            let installDate = ctx.globalState.get(INSTALLATION_DATE);
            if (uuid === undefined) {
                console.log("UUID undefined. Shouldn't happen.");
                uuid = uuidv4();
                ctx.globalState.update(INSTALLATION_UUID, uuid);
            }
            if (installDate === undefined) {
                console.log("Install date undefined. Shouldn't happen.");
                installDate = (new Date(lastUpdatedDate)).toISOString();
                ctx.globalState.update(INSTALLATION_DATE, installDate);
            }
            await sendEvent("subsequent", uuid as string, installDate as string, recentViews);
            ctx.globalState.update(LAST_UPDATED_DATE, today);
            recentViews = 0;
        }
        ctx.globalState.update(RECENT_VIEWS, recentViews);
    }
}

function differentDay(d1: Date, d2: Date) {
    return d1.getDate() !== d2.getDate() ||
           d1.getMonth() !== d2.getMonth() ||
           d1.getFullYear() !== d2.getFullYear();
}

async function sendEvent(eventType: string, uuid: string, installDate: string, views: number | undefined) {
    try {
        const data = {
            uuid: uuid,
            eventType: eventType,
            timestamp: Date(),
            createdAt: installDate,
            os: process.platform,
            arch: process.arch,
            packaging: "unknown",
            views: views,
            version: util.getVersion(),
        };

        await axios.post(URL, data, {
            headers: {
                // eslint-disable-next-line @typescript-eslint/naming-convention
                'User-Agent': util.getUserAgent(),
            },
        });
    } catch(e) {
        console.log("Telemetry error", e, "for event", eventType);
    }
}