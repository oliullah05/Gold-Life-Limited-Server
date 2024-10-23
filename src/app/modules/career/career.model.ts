import { Schema, model } from 'mongoose';


const createCareerSchema = new Schema({
    title: { type: String, required: true },

    about: { type: String, required: true },
    keyResponsibilities: { type: [String], required: true },
    knowledgeSkillExpertise: { type: [String], required: true },
    experience: { type: [String], required: true },
    deadline: { type: String, required: true },
    employmentType: { type: String, required: true },
    location: { type: String, required: true },
    workPlace: {
        type: String,
        enum: ['Hybrid', 'Onsite', 'Work from home'],
        required: true
    },
    salary: { type: String, required: true },
}, {
    timestamps: true
});


export const CareerModel = model('Career', createCareerSchema);
