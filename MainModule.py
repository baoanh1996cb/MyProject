import CaptureModule
import FeatureExtractModule
import MyTestModule
from multiprocessing import Process

if __name__ == "__main__":
    try:
        # processCapture = Process(target = CaptureModule.capture(), name=("processCapture"))
        # processFeature = Process(target = FeatureExtractModule.featureExtract(), name=("processFeature"))
        processTest = Process(target=MyTestModule.featureExtract())
        # processCapture.start()
        # processFeature.start()
        processTest.start()
    except KeyboardInterrupt:
        # processCapture.stop()
        # processFeature.stop()
        processTest.stop()

    # processCapture.join()
    # processFeature.join()
    processTest.join()
