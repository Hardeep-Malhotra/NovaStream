import { asyncHandler } from "../utils/asyncaHandler.js";
import { ApiError } from "../utils/ApiError.js";
import jwt from "jsonwebtoken";   // <-- FIXED
import { User } from "../models/user.model.js";

export const verifyJWT = asyncHandler(async (req, res, next) => {
    try {
        const token =
            req.cookies?.accessToken ||
            req.header("Authorization")?.replace("Bearer ", ""); // <-- extra space

        if (!token) {
            throw new ApiError(401, "Unauthorized request");
        }

        // FIX: JWT.verify → jwt.verify
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        // FIX: findByID → findById
        // FIX: "-passwrod -refreshTokem" → correct spelling
        const user = await User.findById(decodedToken?._id).select(
            "-password -refreshToken"
        );

        if (!user) {
            throw new ApiError(401, "Invalid Access Token");
        }

        req.user = user;
        next();
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid access token");
    }
});
