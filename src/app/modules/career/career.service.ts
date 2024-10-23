import { TCareer } from "./career.interface"
import { CareerModel } from "./career.model"

const createJobPostInDB = async (data: TCareer) => {
    const result = await CareerModel.create(data)
    return result
}

const getAllJobPostsInDB = async () => {
    const result = await CareerModel.find();
    return result
}

export const careerServices = {
    createJobPostInDB,
    getAllJobPostsInDB
}