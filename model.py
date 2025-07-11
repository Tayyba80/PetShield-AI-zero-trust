from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image
import numpy as np
import io
from PIL import Image

#model = load_model('dogcat_model_resaved.h5', compile=False)

def predict_image(file_data):
    try:
        # Convert binary data to a PIL image
        img = Image.open(io.BytesIO(file_data))
        img = img.resize((64, 64))
        img_array = image.img_to_array(img)
        img_array = np.expand_dims(img_array, axis=0) / 255.0

        prediction = model.predict(img_array)
        confidence = max(prediction[0])

        if confidence < 0.7:
            return "Sorry, not sure if it's a cat or dog. 🤔 Please upload a clearer pet image."

        if prediction[0][0] > 0.5:
            return f"It's a Dog 🐶 (Confidence: {prediction[0][0]*100:.2f}%)"
        else:
            return f"It's a Cat 🐱 (Confidence: {prediction[0][1]*100:.2f}%)"
    
    except Exception as e:
        print("Prediction Error:", e)
        return "Error reading the uploaded image. Please try again."
