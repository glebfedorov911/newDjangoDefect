import uuid


class ExcludeHoursProfile:
    def __init__(
            self,
            name: str,
            exclude_hours_id: uuid.UUID,
            time_offset: int,
            exclude_hours: list[dict]
    ):
        self.name = name
        self.exclude_hours_id = exclude_hours_id
        self.time_offset = time_offset
        self.exclude_hours = exclude_hours

    def body(self):
        return {
            "name": self.name,
            "excluded_hours_id": str(self.exclude_hours_id),
            "time_offset": self.time_offset,
            "exclusion_matrix": ExcludeHoursConverter(self.exclude_hours).to_matrix()
        }


class ExcludeHoursConverter:
    HOURS_IN_WEEK = 168
    HOURS_IN_DAY = 24


    def __init__(self, exclude_hours: list[dict]):
        self.exclude_hours = exclude_hours

    def to_matrix(self) -> list:
        matrix_exclude_hours = [False] * self.HOURS_IN_WEEK

        if not self.exclude_hours:
            return matrix_exclude_hours
        
        for exclude_hour in self.exclude_hours:
            day_of_week = self._get_day_of_week_decrement(exclude_hour)
            for hour in self._get_range_hours(exclude_hour):
                _exclude_hour = self._get_index_hour_exclude(day_of_week, hour)
                matrix_exclude_hours[_exclude_hour] = True

        return matrix_exclude_hours

    @staticmethod
    def _get_day_of_week_decrement(exclude_hour: dict):
        try:
            return int(exclude_hour.get("day_of_week")) - 1
        except TypeError:
            raise ValueError("Input bad type for day of week")
        
    @staticmethod
    def _get_range_hours(exclude_hour: dict):
        try:
            return range(
                int(exclude_hour.get("start_time"))-1, 
                int(exclude_hour.get("finish_time"))
            )
        except TypeError:
            raise ValueError("Input bad type for start or finish times")

    def _get_index_hour_exclude(self, day_of_week: int, hour: int):
        try:
            return int(day_of_week) * self.HOURS_IN_DAY + int(hour)
        except TypeError:
            raise ValueError("Input bad type for day of week or hour")
        

