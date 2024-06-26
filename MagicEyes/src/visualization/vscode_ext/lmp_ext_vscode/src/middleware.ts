import { Response, Request, NextFunction } from "express";

export function detectRequestSource(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const userAgent = req.headers["user-agent"];

  if ((userAgent?.includes("Code") || userAgent?.includes("code"))
      && userAgent?.includes("Electron")) {
    next();
  } else {
    res.status(403).send("Access Denied");
  }
}
