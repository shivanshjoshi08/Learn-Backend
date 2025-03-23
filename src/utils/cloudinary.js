import { v2 as cloudinary } from "cloudinary";
import fs from 'fs'


cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const uplaodOnCloudinary = async(localFilePath) => {
    try {
        if (!localFilePath) {
            return null
        }
         // Upload file to Cloudinary
        const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type: "auto"
        })
        console.log("file is uploaded on cloudinary,response.url");
        return response;

    } catch (error) {
        fs.unlinkSync(localFilePath) //remove the locally saved temporary file as the upload operation gotfailed
        return null;
    }
}


// cloudinary.v2.uploader.upload("https://upload.wikimedia.org/wikipedia.commons/a/ae/Olympic_flag.jpg", { public_id: "olympic_flag" }, function (error, result) {
//     console.log(result);
// });

// cloudinary.v2.uploader.upload("https://upload.wikimedia.org/wikipedia.commons/a/ae/Olympic_flag.jpg", { public_id: "olympic_flag" }, function (error, result) {
//     console.log(result);
// });