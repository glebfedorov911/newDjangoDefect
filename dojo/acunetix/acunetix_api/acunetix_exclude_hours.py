

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

    def _get_day_of_week_decrement(exclude_hous): ...