import httpStatus from "http-status";
import catchAsync from "../../utils/catchAsync";
import sendResponse from "../../utils/sendResponse";
import { careerServices } from "./career.service";

const createJobPost = catchAsync(async (req, res) => {
    const result = await careerServices.createJobPostInDB(req.body)

    sendResponse(res, {
        statusCode: httpStatus.OK,
        success: true,
        message: 'Job post created successfully!',
        data: result
    })
});

const getAllJobPosts = catchAsync(async (req, res) => {
    const result = await careerServices.getAllJobPostsInDB()

    sendResponse(res, {
        statusCode: httpStatus.OK,
        success: true,
        message: 'All Job post retrieve successfully!',
        data: result
    })
});

export const careerCollections = {
    createJobPost,
    getAllJobPosts
}