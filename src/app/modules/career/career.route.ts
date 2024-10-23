import express from 'express';
// import auth from '../../middlewares/auth';
import { careerCollections } from './career.collaction';

const router = express.Router();

router.post(
    '/',
    // auth('admin'),
    careerCollections.createJobPost

);

router.get(
    '/',
    careerCollections.getAllJobPosts
)

export const careerRoutes = router;