from fastapi.responses import StreamingResponse


class StreamAdapter:

    @staticmethod
    def to_streaming_response(generator):
        return StreamingResponse(generator, media_type="text/plain")
