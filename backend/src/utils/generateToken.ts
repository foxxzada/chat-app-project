import jwt from "jsonwebtoken";
import type { Response } from "express";

const generateToken = (userId: string, res: Response) => {
  // biome-ignore lint/style/noNonNullAssertion: <explanation>
  const token = jwt.sign({ userId }, process.env.JWT_SECRET!, {
    expiresIn: "15d",
  });

  res.cookie("jwt", token, {
    maxAge: 15 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV !== "development",
  });

  return token;
};

export default generateToken;
